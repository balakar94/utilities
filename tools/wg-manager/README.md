# wg-manager

> Guided native WireGuard server manager for Debian, RHEL, Fedora and Arch operators.

Owner: `@balakar94` | Last-verified: `2026-09-14` | Status: `incubating` | License: `Apache-2.0`

## Use for

- Native WireGuard hub with networkd or NetworkManager, never a wg-quick daemon.
- Permanent router links first, then on-demand QR clients with custom pools.

## Not for

- Web UIs like wg-easy -> CLI only.
- Non-Linux hosts or resale VPN -> scoped Linux forwarding only.

## Requirements

- `python >= 3.11` stdlib only; `bash` for `install.sh`.
- `wireguard-tools` (`wg`) for keys; supported firewall engines: `nftables`, `firewalld`, or `ufw`; `qrencode` optional.
- `WG_MANAGER_STATE` override; `--lang auto|en|es|de`; no network for dry-run/self-test.

## Impact

- Level `system`. Writes binary (`0755`), `/etc/wg-manager/state.json` and `clients/*` (`0600`, dirs `0700`),
  network units, firewall rules, sysctl.
- Dry-run by default; `--apply --yes [--sudo]`; non-interactive `init --apply` needs `--set`.
- Real keys via `wg genkey`/`wg pubkey`; renders refuse placeholder private keys.
- Multi-firewall integration: safe tagged rules (`comment "wg-manager"`) in host `table inet filter` for
  `nftables`, `trusted` zone assignment in `firewalld`, and native route/port rules in `ufw`.
- Rollback: state and `sys-*` backups keep 20, `.bak` stamps, manifest, `rollback --to`, `install.sh --restore`.
  Multi-engine cleanup on uninstall.

## Quickstart

```bash
bash tools/wg-manager/install.sh --dry-run
bash tools/wg-manager/install.sh --apply --yes --sudo
wg-manager --self-test
wg-manager init --dry-run
wg-manager menu
```

Expected: installer plan then `SELF-TEST PASS` then dry-run preview, exit `0`.

## Commands reference

All commands are dry-run by default. Pass `--apply --yes [--sudo]` to commit changes to disk or system network units.

### Interactive Console & Setup

- `menu`: Full-screen TUI cockpit dashboard. Shows live status, telemetry summary, peers preview, and supports
  numeric selection (`1`..`18`, `0`) or quick mnemonic letter shortcuts (`a` add, `l` list, `s` status, `c` check,
  `r` reload, `b` backup, `q` quit).

  ```bash
  wg-manager menu
  ```

- `init`: First-time server setup wizard. Prompts for endpoint, UDP port, MTU, interface name, network backend
  (`networkd` or `NetworkManager`), firewall (`nftables` or `firewalld`), and IPv4/IPv6 pool ranges.
  - Flags: `--force` (overwrite existing state), `--import-server-key <path>` (use existing private key), `--set
    key=value` (scripted non-interactive setup).

  ```bash
  wg-manager init --dry-run
  wg-manager init --apply --yes --sudo --set endpoint=vpn.example.com --set port=51820
  ```

### Peer Lifecycle & IPAM

- `add`: Add a new peer with guided IP allocation. In the interactive wizard, prompts for pre-shared key (PSK)
  generation (default Yes for post-quantum security). Under `nat66` mode (even with a single WAN `/128`), clients
  automatically receive a local ULA address (`fd90:90:90::/64`) and full-tunnel peers route `::/0` via server NAT66
  masquerading.
  - Flags: `--name <name>` (peer identifier), `--kind client|infra` (role), `--pool <name>` (target IP pool),
    `--traffic server-only|custom-routes|full-tunnel`, `--routes <cidr,cidr>`, `--dns-scope none|tunnel|all`,
    `--keepalive <sec>`, `--ip <ipv4>`, `--ip6 <ipv6>`, `--psk [key]` (generate or provide PSK), `--no-psk` (skip
    PSK), `--expires <duration|date>`.

  ```bash
  wg-manager add --name phone --kind client --traffic full-tunnel --psk
  wg-manager add --name branch-router --kind infra --pubkey "PUBKEY..." --ip 10.90.90.10
  ```

- `list`: Display an aligned overview of all configured peers sorted permanents-first, including name, role,
  assigned IPv4, IPv6, and operational status (`active`, `disabled`, `tombstoned`).

  ```bash
  wg-manager list
  ```

- `edit`: Modify peer attributes in place. Supports key rotation, traffic profile updates, pool migration, and IP
  reallocation.
  - Flags: `[name]`, `--new-name <name>`, `--endpoint <host:port>`, `--traffic <mode>`, `--routes <list>`,
    `--keepalive <sec>`, `--rotate-keys` (generates fresh keys), `--keep-psk`, `--reclaim-ip`.

  ```bash
  wg-manager edit phone --traffic split --keepalive 25
  wg-manager edit phone --rotate-keys
  ```

- `enable` / `disable`: Temporarily pause or re-activate a peer on the WireGuard interface without releasing its
  assigned IP address.

  ```bash
  wg-manager disable phone
  wg-manager enable phone
  ```

- `delete`: Tombstone a peer. Marks the peer inactive and removes it from the WireGuard interface configuration,
  but keeps its IP address reserved in state to prevent accidental IP reassignment.

  ```bash
  wg-manager delete phone
  ```

- `reclaim`: Release a tombstoned peer's reserved IP address back into the free IP pool.

  ```bash
  wg-manager reclaim phone
  ```

- `purge`: Permanently delete tombstoned peers from the state file and free their addresses.
  - Flags: `--pool <name>` (optional pool filter).

  ```bash
  wg-manager purge
  ```

### Client Configuration & QR

- `show`: Display rendered client WireGuard configuration file (`wg0.conf`). Sensitive private keys and pre-shared
  keys are redacted with asterisks by default.
  - Flags: `[name]`, `--show-secrets` (reveal keys in plaintext).

  ```bash
  wg-manager show phone
  wg-manager show phone --show-secrets
  ```

- `qr`: Generate and print an ASCII QR code in the terminal for mobile device configuration scanning (iOS and
  Android WireGuard apps).

  ```bash
  wg-manager qr phone
  ```

- `export`: Export ready-to-use client `.conf` files to disk with restrictive `0600` permissions.
  - Flags: `[name]`, `--all` (export all enabled clients), `--out-dir <dir>` (destination directory).

  ```bash
  wg-manager export phone --out-dir ~/wireguard-clients
  wg-manager export --all --out-dir /etc/wireguard/clients
  ```

### Server Operations & Telemetry

- `status`: Query live WireGuard kernel interface via `wg show <ifname> dump`. Displays latest handshake age,
  transfer byte counters, and active remote endpoints.

  ```bash
  wg-manager status
  ```

- `reload`: Render native network backend units (`systemd.netdev`/`network` with dual `IPForward`/`IPv4Forwarding`
  and networkd drop-in, or NetworkManager keyfiles) and firewall rules, apply changes, perform in-kernel live peer
  synchronization via `wg syncconf`, and verify link health with automatic rollback on failure.
  - Multi-firewall integration:
    - **`nftables`**: Renders pure unified `table inet wg_manager` with scoped NAT masquerade (`oifname !=
      <ifname>`). Integrates with host `table inet filter` by adding tagged rules (`comment "wg-manager"`) to
      prevent host-level drop policy conflicts.
    - **`firewalld`**: Adds interface to the `trusted` zone (`--zone=trusted --add-interface=<ifname>`) preventing
      inter-zone forwarding drops in firewalld $\ge 0.9.0$, opens listen port, and enables masquerade.
    - **`ufw`**: Detects active UFW daemon, allowing the UDP listen port and interface routed forwarding (`ufw
      route allow in on <ifname>`).
  - Flags: `--backend networkd|nm`, `--firewall nft|firewalld`.

  ```bash
  wg-manager reload --dry-run
  wg-manager reload --apply --yes --sudo
  ```

- `check`: Run comprehensive system health checks. Verifies Curve25519 key shapes, IPv4 forwarding sysctl
  (`net.ipv4.ip_forward=1`), backend daemon status, and audits firewall engines:
  - **`nftables`**: Detects if host `table inet filter` has a drop policy and verifies presence of `wg-manager`
    input/forward rules.
  - **`firewalld`**: Verifies if running and checks whether `<ifname>` is assigned to the `trusted` zone.
  - **`ufw`**: Verifies if active and validates that the WireGuard port and routing rules are allowed.

  ```bash
  wg-manager check
  ```

- `reconfigure`: Update server-level networking configuration (public endpoint hostname/IP, listen port, MTU, IPv6
  operational mode). Warns when client configurations require QR regeneration.
  - Flags: `--endpoint <host>`, `--port <port>`, `--mtu <mtu>`, `--ipv6-mode disabled|ula|delegated`.

  ```bash
  wg-manager reconfigure --endpoint vpn2.example.com --dry-run
  ```

### Safety, Backup & Recovery

- `backup`: Create an atomic snapshot of `/etc/wg-manager/state.json` stored in `/var/backups/wg-manager/` (keeps
  latest 20 backups automatically).
  - Flags: `--output <path>` (custom target path).

  ```bash
  wg-manager backup
  ```

- `rollback`: Restore a previous state snapshot and roll back system network configuration.
  - Flags: `--list` (show available backups with timestamps), `--to <path>` (target backup file).

  ```bash
  wg-manager rollback --list
  wg-manager rollback --to /var/backups/wg-manager/state.json.bak.20260914120000 --apply --yes --sudo
  ```

- `uninstall` / `--uninstall`: Remove all server configuration, WireGuard interface, sysctl files, firewall rules,
  and state directory (`/etc/wg-manager`), resetting the server to a clean default state for a fresh start or
  reinstall. Does not remove the `wg-manager` binary itself.
  - Cleans up across all firewall engines: deletes `wg_manager` nftables tables and tagged rules in host `inet
    filter`, removes interface and port from firewalld, and deletes UFW route and port rules.
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
- `--sudo`: Escalate with `sudo -n` when not executed as root.
- `--dry-run`: Explicitly run in preview mode; renders configuration documents without writing.
- `--show-secrets`: Print sensitive private keys and pre-shared keys in stdout instead of redacting.
- `--lang {auto,en,es,de}`: Force language or auto-detect system locale.
- `--color {always,auto,never}` / `--no-color`: Control ANSI color output.
- `--width <N>`: Set column wrapping width for narrow or wide terminals (clamped 40-200, default 80).
- `--self-test`: Run offline audit verifying key formats, nftables safety, regexes, and IPAM allocation.
- `--version`: Print program name and version (`1.0.0`).
- `--help`: Display usage syntax and subcommand list.

## Firewall & Routing Architecture

`wg-manager` is designed to be complementary and non-destructive to host network configurations:

- **`nftables` (Arch Linux, Debian, Alpine)**:
  - Manages isolated tables `inet wg_manager`, `ip wg_manager_nat4`, and `ip6 wg_manager_nat6`.
  - Scoped NAT: Masquerades traffic only when exiting through non-WireGuard interfaces (`oifname != <ifname>`).
  - Base Chain Coexistence: Automatically integrates with existing host filter tables (e.g., `/etc/nftables.conf`
    with `policy drop`) by inserting tagged rules (`comment "wg-manager"`). On uninstall, only tagged rules are
    removed.
  - MSS Clamping: Dynamic `tcp flags syn tcp option maxseg size set rt mtu` adapts segment size to route MTU.
- **`firewalld` (RHEL, Fedora, CentOS, AlmaLinux, Rocky)**:
  - Automatically places the WireGuard interface into the `trusted` zone. This resolves inter-zone forwarding drops
    introduced in firewalld $\ge 0.9.0$.
  - Opens UDP listen port and enables masquerading on the active WAN zone.
  - Applies TCPMSS clamping via `--clamp-mss-to-pmtu` in forward chains.
  - Cleanly removes the interface from `trusted`, closes the UDP port, and removes direct MSS rules on uninstall.
- **`ufw` (Ubuntu, Debian)**:
  - Inter-operates with active UFW installations without modifying core `/etc/default/ufw` files.
  - Automatically applies `ufw allow <port>/udp comment "wg-manager"` and `ufw route allow in on <ifname>`.
  - Deletes both rules upon `uninstall`.
- **MSS Clamping & MTU Mechanics (IPoE vs PPPoE)**:
  - Server uplinks typically use IPoE (MTU 1500), where default WireGuard MTU is 1420 (leaving 80 bytes for
    IPv6/WireGuard envelope).
  - Residential/fiber uplinks often use PPPoE (MTU 1492), requiring a WireGuard MTU of 1412.
  - `wg-manager check` inspects WAN MTU and alerts if WireGuard MTU exceeds `max(1280, wan_mtu - 80)`.
  - Both `nftables` (`set rt mtu`) and `firewalld` (`--clamp-mss-to-pmtu`) automatically adjust TCP SYN packets,
    eliminating MTU blackholes.
- **SELinux & AppArmor Support**:
  - **SELinux**: System unit files and state writes automatically invoke `restorecon -F` to ensure correct SELinux
    security contexts (`systemd_networkd_unit_file_t`, `NetworkManager_etc_rw_t`, `etc_t`). Audited in `wg-manager
    check`.
  - **AppArmor**: Operates seamlessly with AppArmor; WireGuard runs in-kernel without user-space confinement
    issues. Audited in `wg-manager check`.
- **IPv6 Dual-Stack Modes**:
  - `disabled`: IPv6 networking completely omitted; only IPv4 allocated.
  - `ula`: Assigns unique local IPv6 addresses (`fd90:90:90::/64`) for local peer-to-peer and peer-to-server
    traffic. Completely agnostic of external IPv6 internet; no NAT66 applied.
  - `routed`: Used when a dedicated public `/64` prefix is routed exclusively to the WireGuard server. Packets are
    routed end-to-end natively without any NAT.
  - `nat66`: Tailored for VPS providers offering only a single `/128` (e.g. IONOS, Hetzner Cloud). Assigns internal
    ULA addresses to clients and masquerades outbound client IPv6 traffic through the server's single WAN IPv6
    address.
- **Systemd Forwarding & Reverse Path Filtering**:
  - Emits dual systemd network keys `IPForward=yes` and `IPv4Forwarding=yes` for universal systemd support (v245
    through v256+).
  - Configures `/etc/systemd/networkd.conf.d/80-wg-manager.conf` for host-wide networkd packet forwarding.
  - Configures loose reverse path filtering (`net.ipv4.conf.all.rp_filter = 2` and `default.rp_filter = 2`) to
    enable asymmetric tunnel routing without packet drops.

## Limits & status

- CI is offline; live handshakes need staging VMs.
- RHEL may need EPEL for `wireguard-tools`.
- Changing IPv6 mode invalidates addresses; regenerate every QR and router file.

## License & credits

License: `Apache-2.0` · Owner: `@balakar94` · Contact: `@balakar94`
