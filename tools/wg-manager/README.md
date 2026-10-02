# wg-manager

> Guided native WireGuard server manager for Debian, RHEL, Fedora and Arch operators.

Owner: `@balakar94` | Last-verified: `2026-09-24` | Status: `incubating` | License: `Apache-2.0`

## Use for

- Native WireGuard hub with networkd or NetworkManager, never a wg-quick daemon.
- Permanent router links first, then on-demand QR clients with custom pools.

## Not for

- Web UIs like wg-easy -> CLI only.
- Non-Linux hosts, Alpine (no systemd), or resale VPN -> scoped Linux forwarding only.

## Requirements

- `python >= 3.11` stdlib only; `bash` for `install.sh`.
- `wireguard-tools` (`wg`) for keys; one of `nftables`, `firewalld`, or `ufw`; `qrencode` optional.
- `WG_MANAGER_STATE` overrides the state path; `WG_MANAGER_SYSROOT` is a test-only seam that redirects
  system paths. `--lang auto|en|es|de`; dry-run and `--self-test` need no network.

## Impact

- Level `system`. Writes the manager binary (`0755`, default `/usr/local/bin/wg-manager`), the install
  manifest at `/var/lib/wg-manager/install-manifest.json`, and state at `/etc/wg-manager/state.json`
  plus `clients/*` (`0600`, dirs `0700`).
- System paths: `/etc/systemd/network/90-<ifname>.netdev` and `.network`,
  `/etc/systemd/networkd.conf.d/80-wg-manager.conf`,
  `/etc/NetworkManager/system-connections/wg-manager.nmconnection`, `/etc/sysctl.d/90-wg-manager.conf`,
  `/etc/nftables.d/90-wg-manager.nft`, and `/etc/nftables.conf` (or `/etc/sysconfig/nftables.conf` on
  RHEL). Also applies live sysctl values, firewall rules, and the WireGuard interface.
- `install.sh --apply` installs distro packages and the zipapp under the chosen `--prefix`
  (default `/usr/local`); `install.sh --verify` re-checks the installed binary against the manifest
  `binary_sha256`.
- Real backups live under the state dir (`/etc/wg-manager/backups/`), never `/var/backups/`: `state-*`,
  `sys-*`, and `manual-*` each keep the latest 20; `audit.log` rotates to `audit.log.1` above 1 MiB.
- Rollback: `rollback --to <snapshot>` restores state and re-applies the network configuration;
  `install.sh --restore` reverts the binary; `uninstall` restores the sysctls captured at first apply.
- Privileges: dry-run by default; writes require `--apply --yes` plus root or `--sudo`.

## Quickstart

```bash
bash tools/wg-manager/install.sh --dry-run
bash tools/wg-manager/install.sh --apply --yes --sudo
wg-manager --self-test
wg-manager init --dry-run
wg-manager menu
```

Expected: installer plan, then `SELF-TEST PASS`, then a dry-run preview; exit `0`.

## Commands reference

All commands are dry-run by default; `--apply --yes [--sudo]` commits changes, and `--dry-run` always wins
over `--apply`. `list`, `check`, and `status` accept `--json`.

### Metrics & Bulk Operations

- `metrics`: Read-only Prometheus exporter. Renders `wg_manager_*` gauges/counters
  (`interface_present`, `peers_total`, `peers_active`, `peers_online`,
  `peers_expiring_7d`, per-peer `handshake_age_seconds`, `rx/tx_bytes_total`,
  `enabled`, `expired`) plus `--format json`. `--out FILE` writes the textfile
  (atomically, `0644`) for a node_exporter textfile collector; no daemon listens.

  ```bash
  wg-manager metrics
  wg-manager metrics --out /var/lib/node_exporter/textfile/wg_manager.prom
  ```

- `peers`: Bulk, idempotent peer import from JSON, NDJSON or stdin (`--file`, `--format
  auto|json|ndjson`, `--upsert`). Same validation and secret rules as `add`/the spec.

  ```bash
  wg-manager peers --file peers.json --apply --yes --sudo
  printf '%s\n' '{"name":"vpn1","role":"client"}' | wg-manager peers --file - --format ndjson
  ```

- Structured audit logs: set `WG_MANAGER_LOG_FORMAT=json` to make `audit.log` emit one
  JSON object per line (`ts, level, action, detail, user, pid`). Default stays text.

### Declarative (unattended) Configuration

- `plan`: Read a desired-state spec and print the changes needed to converge,
  without writing anything. `--json` prints `{apiVersion, changed, summary, changes[]}`
  and `--detailed-exitcode` returns `3` when there is drift (`0` when converged).
- `reconcile`: Apply the spec. Idempotent: a converged server reports
  `changed=false` and performs no state write. `--prune` tombstones peers absent
  from the spec (never a hard delete). `--json` prints a machine-readable plan/result
  on stdout; human apply chatter goes to stderr.

  ```bash
  wg-manager plan --config desired.json --json --detailed-exitcode
  wg-manager reconcile --config desired.json --apply --yes --sudo --json
  wg-manager reconcile --config desired.json --apply --yes --sudo --prune
  ```

- Spec format: JSON (canonical), TOML via `tomllib`, or YAML when `PyYAML` is installed.
  `apiVersion` is `wg-manager/v1`; unknown versions are rejected. The document covers
  `server`, `ipv4`, `ipv6`, `pools` (`v4`/`v6`) and `peers`.

  ```json
  {
    "apiVersion": "wg-manager/v1",
    "server": {"endpoint": "vpn.example.com", "port": 51820, "mtu": 1420,
               "ifname": "wg0", "backend": "networkd", "wan_iface": "eth0"},
    "ipv4": {"prefix": "10.90.90.0/24", "hub": "10.90.90.1"},
    "ipv6": {"mode": "disabled"},
    "pools": {"v4": [{"name": "clients", "range": "10.90.90.21-10.90.90.150", "kind": "next-free"}]},
    "peers": [
      {"name": "phone", "role": "client", "traffic": "full-tunnel",
       "psk": {"from_env": "WGM_PHONE_PSK"}},
      {"name": "branch", "role": "infra", "infra_type": "router",
       "ip": "10.90.90.10", "custom_routes": ["192.168.50.0/24"]}
    ]
  }
  ```

- Secrets are never inline in the spec: `psk` accepts `"generate"`, a literal key, or an
  indirection object `{"from_env": "NAME"}` / `{"from_file": "/run/secrets/x"}`. A spec has
  no server private key; `init` keeps owning the key material.

### Interactive Console & Setup
- `menu`: Full-screen TUI cockpit with live status, telemetry, and a peers preview. Starts in DRY-RUN;
  press `A` to toggle `MODE: APPLY`. In APPLY, `delete`, `purge`, and `rollback` require typing the exact
  action word, and the first run asks before writing. Select items by number (`1`..`17`, `0` exits), by
  name (`reconfigure`/`reconfig`), or by shortcut (`a` add, `l` list, `s` status, `c` check, `r` reload,
  `b` backup, `e` edit, `d` delete, `x` export, `w` reconfigure, `?` help, `q` quit).

  ```bash
  wg-manager menu
  ```

- `init`: First-time setup wizard. Prompts for endpoint, UDP port, MTU, interface name, backend
  (`networkd` or `NetworkManager`), WAN interface, IPv4 prefix/hub, IPv6 mode/prefix/hub/WAN, DNS
  servers, and the optional permanent (infra) pool. There is no firewall prompt: the engine is
  auto-detected (RHEL family -> firewalld, else nft).
  - Flags: `--force` (overwrite existing state), `--import-server-key <path>`, `--set key=value`
    (repeatable; non-interactive `--apply` requires every required key).

  ```bash
  wg-manager init --dry-run
  wg-manager init --apply --yes --sudo \
    --set endpoint=vpn.example.com --set port=51820 --set mtu=1420 \
    --set ifname=wg0 --set backend=networkd --set wan_iface=eth0 \
    --set ipv4_prefix=10.90.90.0/24 --set ipv4_hub=10.90.90.1 --set ipv6_mode=disabled
  ```

### Peer Lifecycle & IPAM

- `add`: Add a peer with guided IP allocation. The wizard prompts for a pre-shared key (default yes);
  prefer `--psk generate` or `--no-psk` so a literal key never lands in shell history. Under `nat66`,
  clients get a local ULA (`fd90:90:90::/64`) and full-tunnel peers route `::/0` through server NAT66.
  - Flags: `--name`, `--kind client|infra`, `--infra-type mikrotik|router|server`, `--pool`, `--traffic
    server-only|custom-routes|full-tunnel`, `--routes`, `--dns-scope none|tunnel|all`, `--keepalive
    0-120`, `--endpoint`, `--pubkey`, `--ip`, `--ip6`, `--psk [key]`, `--no-psk`,
    `--expires <duration|date>`.

  ```bash
  wg-manager add --name phone --kind client --traffic full-tunnel --psk generate
  wg-manager add --name branch-router --kind infra --ip 10.90.90.10
  ```

- `list`: Permanents-first table with name, role, IPv4, IPv6, and state (`enabled`, `disabled`,
  `expired`, `reissue`, `tombstoned`). `--json` prints `total`, `active`, `infra`, `clients`,
  `tombstoned`, `reissue`, and `peers[]` (`name`, `role`, `v4`, `v6`, `state`, `enabled`,
  `tombstoned`).

  ```bash
  wg-manager list
  wg-manager list --json
  ```

- `edit`: Rename a peer or change endpoint, traffic profile, routes, DNS scope, keepalive, pool,
  allocation, expiry, and enabled state.
  - Flags: `[name]`, `--new-name`, `--endpoint`, `--traffic`, `--routes`, `--dns-scope`, `--keepalive`,
    `--move-pool`, `--rotate-keys`, `--keep-psk`, `--reclaim-ip`, `--pubkey`, `--expires`, `--enable`,
    `--disable`.

  ```bash
  wg-manager edit phone --traffic custom-routes --keepalive 25
  wg-manager edit phone --rotate-keys
  ```

- `enable` / `disable`: Temporarily pause or re-activate a peer without releasing its assigned address.
  `enable` refuses tombstoned peers (use `reclaim`); `disable` never releases the address.

  ```bash
  wg-manager disable phone
  wg-manager enable phone
  ```

- `delete`: Tombstone a peer. Marks it inactive and removes it from the interface configuration, but
  keeps its IP reserved in state to prevent accidental reassignment.

  ```bash
  wg-manager delete phone
  ```

- `reclaim`: Restore a tombstoned peer with a fresh IPv4 (and IPv6 when the pool exists).
  Refuses peers that are not tombstoned.

  ```bash
  wg-manager reclaim phone
  ```

- `purge`: Permanently delete tombstoned peers from the state file and free their addresses.
  Also removes their generated `.conf`/`.rsc`/`.png` artifacts under the state `clients/` directory.
  - Flags: `--pool <name>` (optional pool filter).

  ```bash
  wg-manager purge
  ```

- `sweep`: Disable expired peers so state, status and renders agree (expired peers are already
  excluded from every WireGuard configuration). A daily systemd timer (`wg-manager-expire.timer`,
  installed automatically while any peer carries an expiry date) runs it; safe to run manually.

  ```bash
  wg-manager sweep --dry-run
  wg-manager sweep --apply --yes --sudo
  ```

### Client Configuration & QR

- `show`: Display the rendered peer configuration. Private and pre-shared keys are redacted with
  asterisks unless `--show-secrets` is passed.
  - Flags: `[name]`, `--show-secrets`.

  ```bash
  wg-manager show phone
  wg-manager show phone --show-secrets
  ```

- `qr`: Generate an ASCII QR code in the terminal for the iOS and Android WireGuard apps; falls back
  to plain text when `qrencode` is missing.

  ```bash
  wg-manager qr phone
  ```

- `export`: Export ready-to-use client `.conf` files (`0600`) using atomic writes that never follow
  symlinks; state-derived names are validated and the destination directory is created `0700`.
  - Flags: `[name]`, `--all` (all enabled clients), `--out-dir <dir>`.

  ```bash
  wg-manager export phone --out-dir ~/wireguard-clients
  wg-manager export --all --out-dir /etc/wireguard/clients
  ```

### Server Operations & Telemetry

- `status`: Query the live WireGuard interface (`wg show <ifname> dump`) for handshake age, transfer
  counters, and active endpoints. `--json` prints `interface`, `interface_present`, `peers[]` (`name`,
  `v4`, `status`, `handshake_seconds` (epoch, kept for compatibility), `handshake_timestamp`,
  `handshake_age_seconds` (`null` when never), `rx_bytes`, `tx_bytes`, `endpoint`, `enabled`, `tombstoned`),
  `online`, and `total`.

  ```bash
  wg-manager status
  wg-manager status --json
  ```

- `reload`: Render native backend units and firewall rules (`nftables`, `firewalld`, or `ufw`), apply,
  sync peers in-kernel via `wg syncconf`, and verify link health with automatic rollback on failure. A
  successful apply records the chosen backend and firewall in state (`server.backend`,
  `server.firewall`); every later system apply, `check`, and `rollback` reuses them.
  - Flags: `--backend networkd|nm`, `--firewall nft|firewalld`.

  ```bash
  wg-manager reload --dry-run
  wg-manager reload --apply --yes --sudo
  ```

- `check`: Run health checks: Curve25519 key shapes, IPv4 forwarding sysctl
  (`net.ipv4.ip_forward=1`), backend daemon status, the active firewall engine (tagged nftables rules
  and drop policies, firewalld `trusted` zone, ufw port/routing), MTU/MSS clamping (configured and
  live), handshake age, peers expiring within 7 days, live-vs-configured peer drift, link kind, and
  state file mode/ownership. Disabled peers are skipped, so they never raise false handshake warnings.
  Extra checks are warn-only: `check` exits `1` only when a check reports `err`, `0` otherwise.
  - `--json` prints `results[].status|message` (`ok`, `warn`, `err`, `skip`) plus `passed`, `warnings`,
    `failed`, `skipped`. Exits `1` when any check reports `err`, `0` otherwise.

  ```bash
  wg-manager check
  wg-manager check --json
  ```

- `reconfigure`: Update server-level networking (public endpoint, listen port, MTU, WAN interface, IPv6
  operational mode/prefix/WAN). Warns when client configurations require QR regeneration.
  - Flags: `--endpoint <host>`, `--port <port>`, `--mtu <1280-9000>`, `--wan <ifname>`, `--ipv6-mode
    disabled|ula|routed|nat66`, `--ipv6-prefix <cidr>`, `--ipv6-wan <addr|prefix>`.

  ```bash
  wg-manager reconfigure --endpoint vpn2.example.com --dry-run
  ```

### Safety, Backup & Recovery

- `backup`: Create an atomic snapshot of `<state_dir>/state.json` under
  `<state_dir>/backups/manual-<timestamp>.json` (`0600`, keeps the latest 20).
  - Flags: `--output <path>` (custom target path).

  ```bash
  wg-manager backup
  ```

- `rollback`: Restore a previous state snapshot and re-apply the network configuration it describes.
  - Flags: `--list` (show state and manual snapshots with timestamps), `--to <path>` (target backup file).

  ```bash
  wg-manager rollback --list
  wg-manager rollback --to /etc/wg-manager/backups/state-20260919T120000-abcd1234.json --apply --yes --sudo
  ```

- `uninstall` / `--uninstall`: Remove the WireGuard interface, network units, sysctl file, firewall
  rules, and the manager-owned state files, resetting the host for a fresh start. Restores
  the sysctl values captured at first apply and removes firewalld rich rules (never a global
  masquerade). Only a state directory carrying the manager marker is removed recursively;
  otherwise only known files are deleted. Does not
  remove the `wg-manager` binary itself.
  - Flags: `--dry-run`, `--apply --yes [--sudo]`.

  ```bash
  sudo wg-manager --uninstall
  wg-manager uninstall --dry-run
  wg-manager uninstall --apply --yes --sudo
  ```

## Global options

- `--uninstall`: Trigger server configuration uninstallation and data wipe.
- `--apply`: Commit writes to disk, systemd units, and firewall rules (default is read-only / dry-run).
- `--yes`: Confirm non-interactive execution without interactive prompts.
- `--sudo`: When not root, re-execute the real entrypoint (installed zipapp or repo `main.py`) through
  `sudo`.
- `--dry-run`: Explicit preview; always wins over `--apply`, so both flags together never write.
- `--show-secrets`: Print private keys and pre-shared keys to stdout instead of redacting.
- `--lang {auto,en,es,de}`: Force language or auto-detect system locale.
- `--color {always,auto,never}` / `--no-color`: Control ANSI color output.
- `--width <N>`: Set column wrapping width (40-200, auto by default).
- `--self-test`: Run offline audit verifying key formats, nftables safety, regexes, and IPAM allocation.
- `--version`: Print program name and version (`1.0.0`).
- `--help`: Display usage syntax and subcommand list.

## Firewall & Routing Architecture

`wg-manager` complements host network configurations without overwriting them:

- **`nftables` (Debian, Ubuntu, Arch)**: manages isolated tables `inet wg_manager`, `ip wg_manager_nat4`,
  and `ip6 wg_manager_nat6`, scopes NAT masquerade to the configured WAN egress (`oifname "<wan>"`), and
  inserts tagged rules (`comment "wg-manager"`) into the host filter table so a host `policy drop` keeps
  working; uninstall removes only tagged rules. MSS is clamped dynamically with
  `tcp flags syn tcp option maxseg size set rt mtu`.
- **`firewalld` (RHEL, Fedora, CentOS, AlmaLinux, Rocky)**: assigns the interface to the `trusted` zone,
  resolving inter-zone forwarding drops introduced in firewalld >= 0.9.0, opens the UDP port in that
  zone, uses source-scoped rich-rule masquerade (no global masquerade), and clamps MSS via
  `--clamp-mss-to-pmtu`. Uninstall removes interface, port,
  rich rules, and direct MSS rules.
- **Policy note (sink use-case)**: the default rules only ever *accept* tunnel traffic; the tool
  never renders a `drop` verdict itself. This is intentional: on a traffic sink the tunnel must
  keep flowing even while external lists block addresses elsewhere (e.g. football blackouts).
  To restrict peer destinations, add your own nftables/firewalld rules and adjust the tagged
  `wg-manager` accepts — the tool will not add default-deny on your behalf.
- **`ufw` (Ubuntu, Debian)**: when active, allows the UDP port and routed forwarding
  (`ufw route allow in on <ifname>`); both rules are deleted on uninstall.
- **MTU mechanics**: IPoE uplinks default to WireGuard MTU 1420; PPPoE (uplink MTU 1492) needs 1412.
  `check` warns when the WireGuard MTU exceeds `max(1280, wan_mtu - 80)`; `reconfigure --mtu` accepts
  `1280-9000`.
- **SELinux & AppArmor**: system unit and config writes run `restorecon -F` for correct contexts; both
  are audited by `check`.
- **IPv6 modes**: `disabled` (IPv4 only), `ula` (`fd90:90:90::/64`, no NAT66), `routed` (public `/64`
  routed natively), `nat66` (single `/128`, ULA clients masqueraded through the WAN address).
- **Systemd forwarding**: writes `/etc/systemd/networkd.conf.d/80-wg-manager.conf` with
  `IPv4Forwarding=yes` (systemd >= 256) or `IPForward=yes` (older), both when the version is unknown,
  plus `IPv6Forwarding=yes` when IPv6 is enabled; sets loose reverse path filtering (`rp_filter = 2`).

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Execution or state failure (`check` also returns `1` when a check reports `err`). |
| `2` | Usage error (bad flags, missing `--yes`, incomplete non-interactive `init`). |
| `3` | Drift detected (`plan --detailed-exitcode` only). |
| `130` | Interrupted (Ctrl-C). |

## Troubleshooting

- `wg: command not found` -> `wireguard-tools` is missing -> install it (`apt install wireguard-tools`,
  `dnf install wireguard-tools`, `pacman -S wireguard-tools`; RHEL may need EPEL).
- `systemd-networkd inactive` -> the selected backend service is not running -> start and enable
  `systemd-networkd`, or re-run with `--backend nm`.
- `nft` absent -> the apply is refused because the nftables engine cannot run -> install `nftables`, or
  select `--firewall firewalld`.
- Peers never handshake -> blocked UDP port, MTU too high, or a key/PSK mismatch -> open the UDP port,
  lower `--mtu` (for example 1412 on PPPoE), and re-issue client configs with `show`/`qr`/`export`.
- State corrupt or invalid -> malformed JSON or a failed schema/type/name validation -> restore with
  `rollback --to <state snapshot>` from `<state_dir>/backups/`.
- `check` in Docker -> a `drop` policy in `ip filter FORWARD` blocks forwarded tunnel traffic -> add an
  accept for `<ifname>` before the drop, or keep WireGuard off that path.

## Compatibility

| Platform | Backend | Firewall |
| --- | --- | --- |
| Debian / Ubuntu | systemd-networkd (or NetworkManager) | nftables or ufw |
| RHEL / Fedora / Alma / Rocky | NetworkManager (`nm`) | firewalld |
| Arch | systemd-networkd | nftables |
| Alpine | not supported (no systemd) | - |

RHEL-family hosts may need EPEL for `wireguard-tools`.

## Security

- State contains server and peer private keys: `state.json` is `0600` inside a `0700` directory, and
  the rotating backups (`state-*`, `sys-*`, `manual-*`, kept to 20 each) carry the same sensitivity.
  `check` warns when the state file mode or root ownership drifts.
- `--show-secrets` prints private and pre-shared keys to stdout; treat that output as sensitive.
- Backups are deliberately **not encrypted**: encryption would just move the secret to a key file
  on the same host (same threat model as the `0600` files), while a lost external key would make
  disaster recovery impossible. If you need it, wrap `<state_dir>/backups` with LUKS/host-level
  encryption; a future `age`-based opt-in needs an external KMS/TPM design first.
- Unattended hardening: the state file must be a regular, root-owned `0600` file and symlinks are
  rejected; a non-root caller keeps the historical behaviour. The state path may not sit directly in
  a system directory (`/etc`, `/var`, ...). The daily expiry timer runs with `NoNewPrivileges=yes`,
  `ProtectHome=yes`, `PrivateTmp=yes` and an absolute `ExecStart`, so it never resolves the binary
  through `PATH` at sweep time.
- `systemd-networkd` reads the `.netdev` as the `systemd-network` user, so it is written `0640`
  `root:systemd-network`: forcing `0600` makes networkd skip the interface (verified on systemd 255).
  The server private key and peer pre-shared keys are therefore readable by that service group; for
  the NetworkManager backend the keyfile stays `0600`.
- `--sudo` re-executes the real entrypoint **before** any handler reads state, so a non-root operator
  can use it even though `/etc/wg-manager` is `0700 root`; without it, a non-root read fails with an
  actionable message instead of a traceback.

## Limits & status

- CI is offline; live handshakes and kernel applies need staging VMs or hosts.
- Changing the IPv6 mode or prefixes invalidates addresses; regenerate every QR and router file.

## License & credits

License: `Apache-2.0` · Owner: `@balakar94` · Contact: `@balakar94`
