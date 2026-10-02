# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). This project uses SemVer.

## [Unreleased]

- Add `wg-manager`: native WireGuard hub manager (networkd/NM, nftables/firewalld, QR clients, EN/ES/DE, dry-
  run-first with rollback).
- `wg-manager` audit hardening: real Curve25519 keys (`wg genkey`/`wg pubkey`), fail-hard render guards,
  strict interface-name validation, idempotent and validated nftables (no injection), apply with post-verify
  and rollback, state `flock`, DNS scope, and installer fixes (manifest via `json.dump`, `--prefix`
  validation, `--uninstall` removes only, new `--restore`).
- `wg-manager` console redesign: a pure, testable presentation layer (`paint`, `section`, `kv`, `table`,
  `note`, `hint`, `items`, `emit`) replaces ad-hoc prints. Aligned peers table, grouped `show`/`check` reports
  with ASCII `[ok]/[warn]/[fail]/[skip]/[dry-run]/[applied]/[danger]` tags, one visual grammar for the menu,
  and a new `--width N` seam. Color stays gated (`NO_COLOR`/`--color`), piped output is plain, and every
  chrome line fits 60/80/120 with ASCII truncation. Presentation-only: exit codes, tags/secret redaction, and
  the `render_*` documents are unchanged; `tests/test_basic.py` adds ASCII, no-ANSI-on-pipe, width, dry-run-
  distinct, menu-token, and i18n-parity checks.
- `wg-manager` apply-path fixes found on a real host: post-verify now waits for the interface after a
  `systemd-networkd` restart instead of checking immediately (the old immediate check rolled a healthy netdev
  back), a failed apply prints a read-only diagnostics block (service state, `networkctl`, `journalctl`,
  config-written), the state file is persisted only after a successful apply (a failed apply no longer leaves
  a `state.json` that blocks the retry), and `init`/`reload` refuse up front when the selected backend service
  is not running under systemd.
- `wg-manager` peer connectivity and firewall fixes: atomic in-kernel live peer synchronization via `wg
  syncconf` prevents `systemd-networkd` from ignoring new peers on running interfaces, clean `udp dport <port>
  accept` in nftables eliminates UDP packet drops and conntrack fragility, NetworkManager renderer now outputs
  `preshared-key` and keepalive, `rp_filter = 2` applied globally (`all` and `default`) to allow asymmetric
  tunnel routes, and i18n translation parity restored.
- `wg-manager` routing and firewall unification: unified nftables into single `table inet wg_manager` with
  interface-scoped masquerading (`oifname != <ifname>`), automatic integration with host base filter table
  (`table inet filter` on Arch/Debian) to prevent drop-policy collision on port 51820 and forwarding, dual
  `IPForward=yes`/`IPv4Forwarding=yes` for universal systemd (v245-v256+) support,
  `/etc/systemd/networkd.conf.d/80-wg-manager.conf` global forwarding drop-in, active kernel nftables
  verification in `_post_verify`, and client traffic default upgraded to `full-tunnel` with DNS fallback.
- `wg-manager` multi-firewall hardening: `firewalld` backend automatically assigns the WireGuard interface to
  the `trusted` zone to eliminate inter-zone forwarding drops in firewalld >= 0.9.0; native UFW support
  automatically allows the UDP listen port and interface routing on Debian/Ubuntu hosts, audits UFW rules in
  `check`, and performs clean rollback on uninstall.
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

### wg-manager

- Correctness and unattended-hardening batch: NetworkManager routes now use the documented
  `routeN=dest/plen,gateway` keyfile form in the matching family section (the semicolon `routes=`
  list produced empty next hops); systemd `[Route]` gateways are chosen by destination family
  (IPv6 routes no longer get an IPv4 next hop); an endpoint carrying `host:port` is split once and
  no longer double-appends the port or brackets a hostname; NetworkManager applies peer changes with
  `nmcli device reapply` plus `wg syncconf`; the state file is trusted only when it is a regular,
  root-owned `0600` file outside system directories (symlinks rejected); the `SYSROOT` seam is
  sanitized; `_mkdir_private` never chmods a pre-existing system parent; the daily expiry timer uses
  an absolute `ExecStart` with `NoNewPrivileges=`, `ProtectHome=` and `PrivateTmp=`; and
  `install.sh --verify` checks the installed binary against the manifest `binary_sha256`. The test
  suite adds renderer, endpoint, state-trust and failure-injection rollback coverage.
- Live-host fixes found while validating on real Ubuntu 24.04 (systemd-networkd + nftables) and
  Fedora 44 (NetworkManager + firewalld): `--sudo` re-executes before any handler reads state, so a
  non-root operator can use it against the `0700 root` state directory (a non-root read now fails
  with an actionable message, not a traceback); `check` no longer reports `firewall-cmd` as missing
  on a firewalld host; and the installer updates the manifest's `binary_sha256` after `--restore`, so
  `--verify` stays consistent with the reinstalled binary. The end-to-end lifecycle (init, add,
  reconfigure, edit, reload idempotency, check, status, sweep, timer lifecycle, uninstall) and the
  NetworkManager `routeN=` route installation were verified on real hosts.
- `wg-manager` declarative unattended layer: new `plan` and `reconcile` commands over a
  desired-state spec (`apiVersion: wg-manager/v1`, JSON canonical; TOML via `tomllib`; YAML when
  `PyYAML` is installed). `plan` is read-only and reports a pure diff (`--json`,
  `--detailed-exitcode` returns `3` on drift); `reconcile` converges idempotently (a converged
  server reports `changed=false` and writes nothing), supports `--prune` (tombstone, never hard
  delete) and emits a clean JSON payload when `--json` is used. Secrets stay out of the spec via
  `{"from_env"}`/`{"from_file"}` indirection. Also fixed: client `custom_routes` are no longer
  advertised server-side or turned into hub FIB routes (they are reached *through* the hub), and
  `check` reports overlapping AllowedIPs across peers.
- `wg-manager` P1 unattended operations: read-only Prometheus exporter (`metrics`, `--format
  json`, `--out` for a node_exporter textfile) with `wg_manager_*` gauges/counters; bulk
  idempotent peer import (`peers --file json|ndjson|-`, `--upsert`); opt-in JSON audit lines
  (`WG_MANAGER_LOG_FORMAT=json`); and `check` now warns when a host default-drop firewall blocks
  hub-initiated NEW flows to peers.
- Single error and dispatch path: handlers raise `WgError` instead of bare `SystemExit`
  (one `HANDLERS` table shared by CLI and TUI, `sweep` reachable from the menu by
  name); CLI/TUI output and exit codes unchanged.
- CLI and safety fixes: `--sudo` re-executes the real entrypoint, `--dry-run`
  prevails over `--apply`, the TUI has an explicit mode with destructive-action
  confirmations, infra-peer `edit` redacts secrets, `check` returns a real exit
  code and supports `--json`, `rollback` re-applies networking, and `reload`
  persists the backend/firewall state.
- State, storage and packaging: validated state with migrations, lock with
  timeout, unified backups and `audit.log` rotation, atomic `export` without
  symlinks, atomic installer with manifest and hash, and sysctl restored on
  uninstall.
- New fake-backed test suite; README examples corrected.

## [0.1.0] - 2026-09-12

### Added

- Base structure: `README.md`, `docs/`, `templates/tool-template/`, `scripts/`, `tools/`.
- Governance: `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `CODEOWNERS`.
- Automation: `scripts/new-tool.sh`, `scripts/list-tools.sh`, `scripts/common.sh`, CI in `.github/workflows/ci.yml`.
- Agent config: `AGENTS.md`, `new-tool` and `verify-tool` skills.
