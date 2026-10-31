# wg-manager: real-host validation matrix

`wg-manager` is a `system` tool. CI covers the offline suite, the renderers, the installer and a
root-run sandbox, but it cannot prove that a live firewalld/networkd/NetworkManager host accepts
handshakes. Run this matrix on disposable VMs before promoting the tool beyond `incubating`.

Record the commit under test, the OS image, the kernel, the systemd and firewall versions, and attach
the `check --json` and `status --json` output to the sign-off.

## Preconditions

- Disposable VM or snapshot with console access (a lost WAN must not lock you out).
- A second client (phone or `wg-quick` host) with a known-good WireGuard config.
- `python3 >= 3.11`, `wireguard-tools`, and the backend/firewall under test installed by the image.
- Start from a clean state: `wg-manager uninstall --dry-run` must report no managed resources.

## Matrix

| # | Platform / backend | Firewall | What to prove |
|---|---|---|---|
| 1 | Fedora or RHEL 9/10, NetworkManager | firewalld | `init`, add, handshake, reboot persistence, reload idempotency, uninstall |
| 2 | Ubuntu 24.04, systemd-networkd | nftables | Same lifecycle, plus MSS clamp on PPPoE-like MTU |
| 3 | Debian 12, systemd-networkd | nftables | Same lifecycle on systemd < 256 |
| 4 | Ubuntu 24.04, NetworkManager | nftables or ufw | Backend switch with `--force` and reboot |
| 5 | Docker/iptables-nft host | `ip filter` drop | `check` warns; `reload` refuses; tagged accepts + flag proceed |
| 6 | Any host, IPv6 `ula`/`routed`/`nat66` | any | Addresses, routes, DNS scope and WAN RA guard |

## Cases (repeat per row)

1. **Install and init**
   - `bash tools/wg-manager/install.sh --apply --yes --sudo` → exit `0`, `--verify` exit `0`.
   - `wg-manager init --apply --yes --sudo ...` → state `0600`, units rendered, `check` exit `0`.
2. **Handshake**
   - Add a peer, export its config, connect from the client.
   - `wg-manager status --json`: `online >= 1`, `handshake_age_seconds < 180`.
   - On firewalld: `firewall-cmd --zone="$(firewall-cmd --get-zone-of-interface=<wan>)" --query-port=<port>/udp` → yes.
3. **Forwarding and NAT**
   - From the client, reach the hub address, the hub LAN and the internet (full-tunnel).
   - Confirm the NAT rule matches only `oifname "<wan>"` and the tunnel prefix.
   - On a default-drop `ip filter` host, confirm `reload` refuses without
     `--accept-unmanaged-firewall` and proceeds after the tagged accepts exist.
4. **Idempotency**
   - `wg-manager reload --apply --yes --sudo` twice; the second run must not churn state or backups.
   - `wg-manager plan --config <spec> --detailed-exitcode` → `0` when converged.
5. **Reboot**
   - Reboot; the interface, routes, DNS and firewall rules must return without manual steps.
6. **Backend migration** (row 4)
   - `wg-manager reload --backend nm --apply --yes --sudo` → refuses without `--force`.
   - Repeat with `--force`; confirm the old backend files are gone, a reboot still converges, and
     only one stack owns the interface.
7. **Rollback and uninstall**
   - `wg-manager rollback --to <backup> --apply --yes --sudo` restores connectivity.
   - `wg-manager uninstall --apply --yes --sudo` removes only manager files; a foreign `90-wg1.netdev`
     and an unrelated file in a custom `WG_MANAGER_STATE` parent must survive.
8. **Timer**
   - Add a peer expiring in the next hour; `systemctl start wg-manager-expire.service` disables it and
     `status` no longer reports it as active.

## Sign-off

| Field | Value |
|---|---|
| Commit | |
| Host / image | |
| Kernel / systemd / firewall | |
| Cases passed | |
| Incidents / rollback used | |
| Validated by | |
| Date | |

Until every row this repository claims to support is signed, `metadata.yaml` stays `incubating` and
the README keeps the `Last-verified` date of the last real-host run.
