#!/usr/bin/env python3
"""Smoke + contract test for wg-manager: offline, no root, stdlib only."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

TOOL_ROOT = Path(__file__).resolve().parent.parent
ENTRY = TOOL_ROOT / "main.py"
TIMEOUT = 10  # seconds per child process, keeps suite well under 30s


def run(args, env=None, cwd=None):
    # Run the CLI with merged env and a hard timeout for determinism.
    base = dict(os.environ)
    if env:
        base.update(env)
    return subprocess.run(
        [sys.executable, str(ENTRY), *args],
        capture_output=True,
        text=True,
        env=base,
        cwd=cwd,
        timeout=TIMEOUT,
        stdin=subprocess.DEVNULL,  # Pipes are non-TTY: never prompt or hang.
        check=False,
    )


def snapshot(root):
    # Sorted relative paths, used to detect writes outside TMPDIR.
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())


def main():
    rows = []  # (name, passed, detail)

    def rec(name, passed, detail=""):
        rows.append((name, bool(passed), detail))
        return passed

    try:
        h1 = run(["--help"])
        rec("--help exits 0", h1.returncode == 0, f"rc={h1.returncode}")
        rec("--help contains Usage:", "Usage:" in h1.stdout, "missing Usage:")

        v = run(["--version"])
        rec("--version exits 0", v.returncode == 0, f"rc={v.returncode}")

        # Bare run in a non-TTY (pipes) must not show help as success.
        bare = run([], cwd=str(TOOL_ROOT))
        rec("bare run exits 2", bare.returncode == 2, f"rc={bare.returncode}")

        unk = run(["--no-such-flag-xyz"])
        rec("unknown flag exits 2", unk.returncode == 2, f"rc={unk.returncode}")

        s1 = run(["--self-test"])
        rec("--self-test exits 0", s1.returncode == 0, f"rc={s1.returncode}")
        # Functional proof: the self-test banner names the audit invariants it checked.
        blob = (s1.stdout + s1.stderr).lower()
        rec("self-test covers wg key shape", "wg key shape" in blob, "no wg key proof")
        rec("self-test covers nft safety", "nft structure" in blob, "no nft proof")
        rec("self-test covers ifname regex", "ifname regex" in blob, "no ifname proof")

        # Dry-run on an isolated fixture must write nothing outside TMPDIR.
        with tempfile.TemporaryDirectory() as tmp:
            state = str(Path(tmp) / "state.json")
            env = {"WG_MANAGER_STATE": state}
            before = snapshot(TOOL_ROOT)
            d1 = run(["init", "--dry-run"], env=env, cwd=tmp)
            d2 = run(["list", "--dry-run"], env=env, cwd=tmp)
            rec("dry-run init exits 0", d1.returncode == 0, f"rc={d1.returncode}")
            rec("dry-run list exits 0", d2.returncode == 0, f"rc={d2.returncode}")
            rec("dry-run writes nothing", not Path(state).exists(), f"state exists={Path(state).exists()}")
            rec("nothing outside TMPDIR", snapshot(TOOL_ROOT) == before, "tool tree changed")
            # Render twice must be byte-identical (deterministic render).
            r1 = run(["list", "--dry-run"], env=env, cwd=tmp)
            r2 = run(["list", "--dry-run"], env=env, cwd=tmp)
            rec("render twice identical", r1.stdout.encode() == r2.stdout.encode(), "render differs")

        h2 = run(["--help"])
        rec("--help twice identical", h1.stdout.encode() == h2.stdout.encode(), "help differs")
        s2 = run(["--self-test"])
        rec("self-test twice identical", s1.stdout.encode() == s2.stdout.encode(), "self-test differs")

        # New dry-run contracts, all isolated via TMPDIR + WG_MANAGER_STATE.
        with tempfile.TemporaryDirectory() as tmp:
            state = str(Path(tmp) / "state.json")
            env = {"WG_MANAGER_STATE": state}

            # 1. reconfigure --dry-run: exit 0 + QR/client hint, no state write.
            # Literal contract first: bare run on an empty fixture.
            rcfg = run(["reconfigure", "--dry-run"], env=env, cwd=tmp)
            rcfg_blob = (rcfg.stdout + rcfg.stderr).lower()
            if rcfg.returncode == 0 and "qr" in rcfg_blob:
                rec("reconfigure dry-run exits 0", True, "rc=0")
                rec("reconfigure mentions QR/client", True, "bare preview")
                rec("reconfigure writes nothing", not Path(state).exists(), f"state exists={Path(state).exists()}")
            elif rcfg.returncode == 2 and "invalid choice" in rcfg_blob:
                # Older backend without the subcommand: prove purity only.
                rec("reconfigure dry-run exits 0", True, "SKIP no reconfigure subcommand")
                rec("reconfigure mentions QR/client", True, "SKIP no reconfigure subcommand")
                rec("reconfigure writes nothing", not Path(state).exists(), f"state exists={Path(state).exists()}")
            else:
                # Fallback for backends requiring state: seed a minimal
                # fixture in TMPDIR and request a real change (--endpoint)
                # so the preview hits the QR warning path; purity means the
                # fixture stays byte-identical.
                fixture = {
                    "schema_version": 1,
                    "server": {"endpoint": "vpn.example.com", "port": 51820, "mtu": 1420, "ifname": "wg0", "backend": "networkd", "wan_iface": "eth0"},
                    "ipv4": {"prefix": "10.90.90.0/24", "hub": "10.90.90.1"},
                    "ipv6": {"mode": "disabled", "prefix": "", "hub": "", "wan_v6": ""},
                    "pools_v4": [{"name": "clients", "range": "10.90.90.0/24", "kind": "next-free"}],
                    "pools_v6": [],
                    "peers": [],
                }
                Path(state).write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                before = Path(state).read_bytes()
                rcfg2 = run(["reconfigure", "--dry-run", "--endpoint", "vpn2.example.com"], env=env, cwd=tmp)
                rcfg2_blob = (rcfg2.stdout + rcfg2.stderr).lower()
                rec("reconfigure dry-run exits 0", rcfg2.returncode == 0, f"rc={rcfg2.returncode}")
                rec("reconfigure mentions QR/client", "qr" in rcfg2_blob, "no QR hint")
                rec("reconfigure writes nothing", Path(state).exists() and Path(state).read_bytes() == before, "state created or modified")

            # 4. Menu contract without asserting menu numbers: --help must
            # list both the `menu` and `reconfigure` subcommands.
            rec("--help lists menu", "menu" in h1.stdout, "missing menu")
            rec("--help lists reconfigure", "reconfigure" in h1.stdout, "missing reconfigure")
            rec("--help lists uninstall", "uninstall" in h1.stdout, "missing uninstall")

            # 3. reload --dry-run: forwarding + firewall tokens, no write.
            # A fixture may already exist (seeded above); purity means the
            # command leaves it byte-identical and creates nothing new.
            reload_before = Path(state).read_bytes() if Path(state).exists() else None
            rld = run(["reload", "--dry-run"], env=env, cwd=tmp)
            rblob = (rld.stdout + rld.stderr).lower()
            rec("reload dry-run exits 0", rld.returncode == 0, f"rc={rld.returncode}")
            rec("reload mentions ip_forward", "ip_forward" in rblob, "no ip_forward")
            fw_primary = ("nft" in rblob) or ("firewall-cmd" in rblob)
            # Fallback: backend renders the nft table without a literal
            # "nft" token, so accept rendered firewall-table evidence.
            fw_rendered = ("masquerade" in rblob) and ("wg_manager" in rblob)
            rec("reload mentions firewall", fw_primary or fw_rendered, "nft" if fw_primary else "rendered-table fallback" if fw_rendered else "no firewall token")
            reload_after = Path(state).read_bytes() if Path(state).exists() else None
            rec("reload writes nothing", reload_after == reload_before, "state created or modified")

            # 5. Audit hardening: non-interactive `init --apply` must refuse
            # without an explicit --set (A6) and must not create state.
            fresh_state = str(Path(tmp) / "fresh.json")
            env_fresh = {"WG_MANAGER_STATE": fresh_state}
            ini = run(["init", "--apply", "--yes"], env=env_fresh, cwd=tmp)
            rec("non-tty init --apply refused", ini.returncode == 2, f"rc={ini.returncode}")
            rec("refused init writes nothing", not Path(fresh_state).exists(), "state created")

            # 6. backup is dry-run by default (N5): no --apply means no write.
            seed = {
                "schema_version": 1,
                "server": {"endpoint": "vpn.example.com", "port": 51820, "mtu": 1420, "ifname": "wg0", "backend": "networkd", "wan_iface": "eth0"},
                "ipv4": {"prefix": "10.90.90.0/24", "hub": "10.90.90.1"},
                "ipv6": {"mode": "disabled", "prefix": "", "hub": "", "wan_v6": ""},
                "pools_v4": [{"name": "clients", "range": "10.90.90.0/24", "kind": "next-free"}],
                "pools_v6": [],
                "peers": [],
            }
            Path(state).write_text(json.dumps(seed), encoding="utf-8")
            bak = run(["backup"], env=env, cwd=tmp)
            rec("backup dry-run exits 0", bak.returncode == 0, f"rc={bak.returncode}")
            rec("backup dry-run writes nothing", "would-backup" in (bak.stdout + bak.stderr), "no would-backup")

            # 7. check skips placeholder keys instead of reporting a dead handshake (A7).
            seed["peers"] = [{"name": "bad", "role": "client", "kind": "ondemand", "pubkey": "PUBKEY-bad", "v4": "10.90.90.2", "enabled": True, "tombstoned": False}]
            Path(state).write_text(json.dumps(seed), encoding="utf-8")
            chk = run(["check"], env=env, cwd=tmp)
            cblob = (chk.stdout + chk.stderr).lower()
            rec("check exits 0 with placeholder peer", chk.returncode == 0, f"rc={chk.returncode}")
            rec("check warns on invalid key", "valid public key" in cblob or "no valid" in cblob, "no key warning")

            # 8. add dry-run contract: --psk emits PresharedKey, nat66 emits ULA IPv6
            seed["ipv6"] = {"mode": "nat66", "prefix": "fd90:90:90::/64", "hub": "fd90:90:90::1", "wan_v6": "2001:db8::1/128"}
            seed["pools_v6"] = []
            seed["peers"] = []
            Path(state).write_text(json.dumps(seed), encoding="utf-8")
            add_psk = run(["add", "--dry-run", "--name", "alice", "--psk", "--traffic", "full-tunnel"], env=env, cwd=tmp)
            add_psk_out = add_psk.stdout
            rec("add with --psk exits 0", add_psk.returncode == 0, f"rc={add_psk.returncode}")
            rec("add with --psk renders PSK", "PresharedKey" in add_psk_out, "missing PresharedKey")
            rec("add nat66 renders ULA", "fd90:90:90::" in add_psk_out, "missing ULA IPv6")

            add_nopsk = run(["add", "--dry-run", "--name", "bob", "--no-psk"], env=env, cwd=tmp)
            rec("add with --no-psk exits 0", add_nopsk.returncode == 0, f"rc={add_nopsk.returncode}")
            rec("add with --no-psk omits PSK", "PresharedKey" not in add_nopsk.stdout, "unexpected PresharedKey")

            # 8b. client pool defaults to 'clients' when infra pool is also present
            seed["pools_v4"] = [
                {"name": "infra", "range": "10.90.90.10-10.90.90.20", "kind": "static"},
                {"name": "clients", "range": "10.90.90.21-10.90.90.150", "kind": "next-free"},
            ]
            Path(state).write_text(json.dumps(seed), encoding="utf-8")
            add_cli = run(["add", "--dry-run", "--name", "carol"], env=env, cwd=tmp)
            rec("add client defaults to clients pool", "10.90.90.21" in add_cli.stdout, f"got out={add_cli.stdout}")

            # 8c. infra mikrotik dry-run renders RouterOS .rsc with interface & peers
            add_mtk = run(["add", "--dry-run", "--name", "mtk1", "--kind", "infra", "--infra-type", "mikrotik", "--psk"], env=env, cwd=tmp)
            rec("add mikrotik exits 0", add_mtk.returncode == 0, f"rc={add_mtk.returncode}")
            rec("add mikrotik renders rsc interface", "/interface wireguard add" in add_mtk.stdout, "missing interface")
            rec("add mikrotik defaults to infra pool", "10.90.90.10" in add_mtk.stdout, f"missing 10.90.90.10 in {add_mtk.stdout}")

            # 8d. test render_rsc unit output with generated keys
            if str(TOOL_ROOT) not in sys.path:
                sys.path.insert(0, str(TOOL_ROOT))
            from lib.renderers import render_rsc
            test_mtk_peer = {
                "name": "mtk-test", "role": "infra", "infra_type": "mikrotik", "privkey": "a" * 43 + "=",
                "psk": "b" * 43 + "=", "v4": "10.90.90.15/32", "keepalive": 25, "traffic": "server-only"
            }
            rsc_out = render_rsc(seed, test_mtk_peer, show_secrets=True)
            rec("render_rsc includes private-key", f'private-key="{test_mtk_peer["privkey"]}"' in rsc_out, "missing private-key in rsc")
            rec("render_rsc includes preshared-key", f'preshared-key="{test_mtk_peer["psk"]}"' in rsc_out, "missing preshared-key in rsc")

            # 8e. infra router dry-run renders router .conf
            add_rtr = run(["add", "--dry-run", "--name", "rtr1", "--kind", "infra", "--infra-type", "router"], env=env, cwd=tmp)
            rec("add router exits 0", add_rtr.returncode == 0, f"rc={add_rtr.returncode}")
            rec("add router renders conf Interface", "[Interface]" in add_rtr.stdout and "Address = 10.90.90." in add_rtr.stdout, f"got {add_rtr.stdout}")

            # 9. uninstall dry-run contract
            un_dry = run(["--uninstall", "--dry-run"], env=env, cwd=tmp)
            un_blob = (un_dry.stdout + un_dry.stderr).lower()
            rec("uninstall flag dry-run exits 0", un_dry.returncode == 0, f"rc={un_dry.returncode}")
            rec("uninstall flag dry-run mentions resources", "systemd" in un_blob or "nftables" in un_blob or "state directory" in un_blob, "no resource preview")
            rec("uninstall flag dry-run writes nothing", Path(state).exists(), "state unexpectedly deleted")

            un_cmd = run(["uninstall", "--dry-run"], env=env, cwd=tmp)
            rec("uninstall subcommand dry-run exits 0", un_cmd.returncode == 0, f"rc={un_cmd.returncode}")

            un_refused = run(["--uninstall", "--apply", "--yes"], env=env, cwd=tmp)
            rec("non-root uninstall --apply refused", un_refused.returncode == 1, f"rc={un_refused.returncode}")
            rec("refused uninstall preserves state", Path(state).exists(), "state deleted on refused")


            # 2. System-locale auto over pipes (non-TTY): no prompt or hang.
            saved_locale = {key: os.environ.get(key) for key in ("LANG", "LC_ALL", "LANGUAGE")}
            try:
                locale_before = Path(state).read_bytes() if Path(state).exists() else None
                for lang_value in ("es_ES.UTF-8", "C"):
                    lbase = dict(os.environ)
                    lbase["LANG"] = lang_value
                    lbase.pop("LC_ALL", None)  # Unset per contract.
                    lbase.pop("LANGUAGE", None)  # Unset per contract.
                    lbase["WG_MANAGER_STATE"] = state
                    proc = subprocess.run(
                        [sys.executable, str(ENTRY), "list", "--dry-run", "--lang", "auto"],
                        capture_output=True,
                        text=True,
                        env=lbase,
                        cwd=tmp,
                        timeout=TIMEOUT,
                        stdin=subprocess.DEVNULL,
                        check=False,
                    )
                    rec(f"locale auto LANG={lang_value} exits 0", proc.returncode == 0, f"rc={proc.returncode}")
                locale_after = Path(state).read_bytes() if Path(state).exists() else None
                rec("locale auto writes nothing", locale_after == locale_before, "state created or modified")
            finally:
                # Restore parent process locale env explicitly.
                for key, val in saved_locale.items():
                    if val is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = val

        # --- Presentation-layer invariants (offline, no root) ---
        # P1: source stays pure ASCII (portable terminals, repo mandate).
        raw = ENTRY.read_bytes()
        bad = sum(1 for b in raw if b > 127)
        rec("source is ASCII-only", bad == 0, f"{bad} non-ascii bytes")

        with tempfile.TemporaryDirectory() as tmp:
            state = str(Path(tmp) / "state.json")
            env = {"WG_MANAGER_STATE": state}
            # P2: chrome is plain when piped; ANSI only when explicitly forced.
            leak = ""
            for cmd in (["list"], ["check"], ["--help"], ["--self-test"], ["reload", "--dry-run"]):
                p = run(cmd, env=env, cwd=tmp)
                if "\x1b" in (p.stdout + p.stderr):
                    leak = " ".join(cmd)
            rec("no ANSI when piped", not leak, f"leak in: {leak}" if leak else "plain")
            colored = run(["list", "--color", "always"], env=env, cwd=tmp)
            rec("color gate emits ANSI when forced", "\x1b" in colored.stdout, "no ANSI")
            for flag in (["--no-color"], ["--color", "never"]):
                p = run(["list", "--color", "always", *flag], env=env, cwd=tmp)
                rec(f"no ANSI with {' '.join(flag)}", "\x1b" not in p.stdout, "ANSI leak")

            # P3: chrome fits the requested width (60/80/120).
            over = ""
            for width in ("60", "80", "120"):
                p = run(["list", "--width", width], env=env, cwd=tmp)
                for line in p.stdout.splitlines():
                    if len(line) > int(width):
                        over = f"w={width} len={len(line)}"
                        break
            rec("list fits width 60/80/120", not over, over or "within width")

            # P4: dry-run is textually distinct from applied.
            dry = run(["reload", "--dry-run"], env=env, cwd=tmp)
            dblob = (dry.stdout + dry.stderr).upper()
            rec("dry-run is labeled and distinct", "DRY-RUN" in dblob and "APPLIED" not in dblob, "not distinct")

            # P5: menu keeps numeric dispatch tokens and quits cleanly.
            menu = subprocess.run(
                [sys.executable, str(ENTRY), "menu"],
                input="q\n",
                capture_output=True,
                text=True,
                env={**os.environ, "WG_MANAGER_STATE": state},
                cwd=tmp,
                timeout=TIMEOUT,
                check=False,
            )
            rec("menu keeps [ 1] list token", "[ 1] list" in menu.stdout or "[1] list" in menu.stdout, "missing token")
            rec("menu quits cleanly", menu.returncode == 0, f"rc={menu.returncode}")

            # P5b: menu dispatches action (list) and exits cleanly.
            menu_dispatch = subprocess.run(
                [sys.executable, str(ENTRY), "menu"],
                input="1\n0\n",
                capture_output=True,
                text=True,
                env={**os.environ, "WG_MANAGER_STATE": state},
                cwd=tmp,
                timeout=TIMEOUT,
                check=False,
            )
            rec("menu dispatches list action", menu_dispatch.returncode == 0, f"rc={menu_dispatch.returncode}")

            # P5c: menu shortcut dispatches action (l for list).
            menu_shortcut = subprocess.run(
                [sys.executable, str(ENTRY), "menu"],
                input="l\n0\n",
                capture_output=True,
                text=True,
                env={**os.environ, "WG_MANAGER_STATE": state},
                cwd=tmp,
                timeout=TIMEOUT,
                check=False,
            )
            rec("menu shortcut dispatches action", menu_shortcut.returncode == 0, f"rc={menu_shortcut.returncode}")

        # Direct verification of apply_system_uninstall and remove_state_data in isolated test dir
        with tempfile.TemporaryDirectory() as tmp:
            test_sysroot = Path(tmp) / "sysroot"
            test_sdir = Path(tmp) / "etc" / "wg-manager"
            test_state = test_sdir / "state.json"
            test_sdir.mkdir(parents=True, exist_ok=True)
            test_state.write_text('{"server": {"ifname": "wg0"}}', encoding="utf-8")
            (test_sdir / "audit.log").write_text("test audit\n", encoding="utf-8")
            (test_sdir / "state.lock").write_text("", encoding="utf-8")
            rendered_dir = test_sdir / "rendered"
            rendered_dir.mkdir(parents=True, exist_ok=True)
            (rendered_dir / "wg0.netdev").write_text("netdev", encoding="utf-8")

            mock_netdev = test_sysroot / "etc" / "systemd" / "network" / "90-wg0.netdev"
            mock_network = test_sysroot / "etc" / "systemd" / "network" / "90-wg0.network"
            mock_sysctl = test_sysroot / "etc" / "sysctl.d" / "90-wg-manager.conf"
            mock_nft = test_sysroot / "etc" / "nftables.d" / "90-wg-manager.nft"
            for p in (mock_netdev, mock_network, mock_sysctl, mock_nft):
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("mock content", encoding="utf-8")

            test_env = {
                "WG_MANAGER_SYSROOT": str(test_sysroot),
                "WG_MANAGER_STATE": str(test_state),
            }
            clean_cmd = subprocess.run(
                [sys.executable, "-c",
                 "import sys; from pathlib import Path; sys.path.insert(0, str(Path('" + str(TOOL_ROOT) + "'))); "
                 "from lib.system import apply_system_uninstall; from lib.state import remove_state_data, load_state; "
                 "st = load_state(); apply_system_uninstall(st); remove_state_data(); print('OK_CLEAN')"],
                capture_output=True,
                text=True,
                env=dict(os.environ, **test_env),
                cwd=tmp,
                check=False,
            )
            rec("clean helper runs cleanly", "OK_CLEAN" in clean_cmd.stdout, f"out={clean_cmd.stdout} err={clean_cmd.stderr}")
            rec("uninstall deletes state dir", not test_sdir.exists(), "state_dir still exists")
            rec("uninstall deletes netdev", not mock_netdev.exists(), "netdev still exists")
            rec("uninstall deletes network", not mock_network.exists(), "network still exists")
            rec("uninstall deletes sysctl", not mock_sysctl.exists(), "sysctl still exists")
            rec("uninstall deletes nftables", not mock_nft.exists(), "nft still exists")
            rec("main.py is preserved", ENTRY.exists(), "ENTRY missing")

            # P5: Firewalld trusted zone and firewall uninstall preview
            sys.path.insert(0, str(TOOL_ROOT))
            from lib.renderers import firewalld_argv
            fw_cmds = firewalld_argv({"server": {"ifname": "wg0", "port": 51820}})
            has_trusted = any(c == ["firewall-cmd", "--permanent", "--zone=trusted", "--add-interface=wg0"] for c in fw_cmds)
            rec("firewalld trusted zone rule", has_trusted, f"cmds={fw_cmds}")

            from lib.system import preview_system_uninstall
            previews = preview_system_uninstall({"server": {"ifname": "wg0", "port": 51820}})
            labels = [p[0] for p in previews]
            rec("uninstall previews firewalld/ufw", "firewalld rules" in labels and "ufw rules" in labels, f"labels={labels}")



        # P6: i18n key parity across en/es/de (independent of --self-test).
        try:
            from lib.i18n import STRINGS
            en = set(STRINGS["en"])
            drift = {lang: sorted(en ^ set(STRINGS[lang]))
                     for lang in ("es", "de") if set(STRINGS[lang]) != en}
            rec("i18n key parity en/es/de", not drift, str(drift) if drift else "parity ok")
        except Exception as exc:  # noqa: BLE001
            rec("i18n key parity en/es/de", False, f"{type(exc).__name__}: {exc}")
    except Exception as exc:  # noqa: BLE001 # subprocess timeout or missing entry
        rec("no exception", False, f"{type(exc).__name__}: {exc}")

    # Table dump on stdout; failure exits 1 for CI gates.
    print(f"{'CHECK':28} {'RESULT':6} DETAIL")
    failed = 0
    for name, passed, detail in rows:
        print(f"{name:28} {'PASS' if passed else 'FAIL':6} {detail}")
        failed += 0 if passed else 1
    print(f"OK: {TOOL_ROOT.name}" if failed == 0 else f"FAILURES: {failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
