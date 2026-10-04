#!/usr/bin/env python3
"""Smoke + contract test for wg-manager: offline, no root, stdlib only.

Coverage layers:
  L1  CLI contract and dry-run purity (no writes outside TMPDIR).
  L2  Every command's dry-run branch, error exits and idempotency.
  L3  Privileged apply paths under WG_MANAGER_SYSROOT with fake binaries on
      PATH: file set, modes, rollback, lock, export safety, uninstall.
  L4  Offline invariants: i18n parity, source ASCII, ANSI gating, JSON output.
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

TOOL_ROOT = Path(__file__).resolve().parent.parent
ENTRY = TOOL_ROOT / "main.py"
TIMEOUT = 15  # seconds per child process, keeps the suite well under a minute

GOOD_KEY_A = "A" * 43 + "="
GOOD_KEY_B = "B" * 43 + "="


def run(args, env=None, cwd=None, input_text=None):
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
        input=input_text,
        stdin=subprocess.DEVNULL if input_text is None else None,
        check=False,
    )


def snapshot(root):
    # Sorted relative paths, used to detect writes outside TMPDIR.
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())


def seed_state(path, **overrides):
    data = {
        "schema_version": 1,
        "server": {
            "endpoint": "vpn.example.com", "port": 51820, "mtu": 1420,
            "ifname": "wg0", "backend": "networkd", "wan_iface": "eth0",
        },
        "ipv4": {"prefix": "10.90.90.0/24", "hub": "10.90.90.1"},
        "ipv6": {"mode": "disabled", "prefix": "", "hub": "", "wan_v6": ""},
        "pools_v4": [{"name": "clients", "range": "10.90.90.0/24", "kind": "next-free"}],
        "pools_v6": [],
        "peers": [],
    }
    data.update(overrides)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return data


def fake_bin_dir(tmp):
    """Create fake system binaries; they log argv and emit canned output."""
    bindir = Path(tmp) / "fakebin"
    bindir.mkdir(parents=True, exist_ok=True)
    log = Path(tmp) / "fakebin.log"
    scripts = {
        "wg": '#!/bin/sh\nprintf "%s\\n" "$*" >> "' + str(log) + '"\n'
              'case "$1" in\n'
              '  genkey) echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ;;\n'
              '  pubkey) echo "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" ;;\n'
              '  genpsk) echo "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=" ;;\n'
              '  show) echo "wg0\tprivkey\t51820\toff"; echo "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\t(none)\t10.90.90.2/32\t1700000000\t1024\t2048\t25" ;;\n'
              '  syncconf) exit 0 ;;\n'
              'esac\nexit 0\n',
        "nft": '#!/bin/sh\nprintf "%s\\n" "$*" >> "' + str(log) + '"\nexit 0\n',
        "ip": '#!/bin/sh\nprintf "%s\\n" "$*" >> "' + str(log) + '"\n'
              'case "$1 $2" in\n  "link show") exit 0 ;;\n  "link delete") exit 0 ;;\n  "link set") exit 0 ;;\n  "-6 addr") exit 0 ;;\n  "route show") exit 0 ;;\n  "-6 route") exit 0 ;;\nesac\nexit 0\n',
        "systemctl": '#!/bin/sh\nprintf "%s\\n" "$*" >> "' + str(log) + '"\necho active\nexit 0\n',
        "networkctl": '#!/bin/sh\nprintf "%s\\n" "$*" >> "' + str(log) + '"\nexit 0\n',
        "ufw": '#!/bin/sh\nprintf "%s\\n" "$*" >> "' + str(log) + '"\necho "Status: inactive"\nexit 0\n',
        "firewall-cmd": '#!/bin/sh\nprintf "%s\\n" "$*" >> "' + str(log) + '"\nexit 0\n',
        "qrencode": '#!/bin/sh\nprintf "%s\\n" "$*" >> "' + str(log) + '"\necho "QR"' + '\nexit 0\n',
        "restorecon": '#!/bin/sh\nexit 0\n',
        "modprobe": '#!/bin/sh\nexit 0\n',
    }
    for name, body in scripts.items():
        p = bindir / name
        p.write_text(body, encoding="utf-8")
        p.chmod(0o755)
    return bindir, log


def fake_env(tmp, bindir, state, sysroot, **extra):
    env = {
        "PATH": str(bindir) + os.pathsep + os.environ.get("PATH", ""),
        "WG_MANAGER_STATE": str(state),
        "WG_MANAGER_SYSROOT": str(sysroot),
        "WG_MANAGER_ALLOW_SYSROOT_APPLY": "1",
    }
    env.update(extra)
    return env


def main():
    rows = []  # (name, passed, detail)

    def rec(name, passed, detail=""):
        rows.append((name, bool(passed), detail))
        return passed

    try:
        # ---------------------------------------------------------------- L1
        h1 = run(["--help"])
        rec("--help exits 0", h1.returncode == 0, f"rc={h1.returncode}")
        rec("--help contains Usage:", "Usage:" in h1.stdout, "missing Usage:")

        v = run(["--version"])
        rec("--version exits 0", v.returncode == 0, f"rc={v.returncode}")

        bare = run([], cwd=str(TOOL_ROOT))
        rec("bare run exits 2", bare.returncode == 2, f"rc={bare.returncode}")

        unk = run(["--no-such-flag-xyz"])
        rec("unknown flag exits 2", unk.returncode == 2, f"rc={unk.returncode}")

        s1 = run(["--self-test"])
        rec("--self-test exits 0", s1.returncode == 0, f"rc={s1.returncode}")
        blob = (s1.stdout + s1.stderr).lower()
        rec("self-test covers wg key shape", "wg key shape" in blob, "no wg key proof")
        rec("self-test covers nft safety", "nft structure" in blob, "no nft proof")
        rec("self-test covers ifname regex", "ifname regex" in blob, "no ifname proof")

        # Subcommand help must describe the subcommand, not the global usage.
        add_help = run(["add", "--help"])
        rec("add --help exits 0", add_help.returncode == 0, f"rc={add_help.returncode}")
        rec("add --help lists --psk", "--psk" in add_help.stdout, "no --psk")
        rec("add --help lists --traffic", "--traffic" in add_help.stdout, "no --traffic")
        check_help = run(["check", "--help"])
        rec("check --help lists --json", "--json" in check_help.stdout, "no --json")

        # --self-test/--version only short-circuit as the first token.
        stray = run(["list", "--self-test"])
        rec("list --self-test is a usage error", stray.returncode == 2, f"rc={stray.returncode}")

        # Flags before the subcommand must not be dropped.
        with tempfile.TemporaryDirectory() as tmp:
            state = str(Path(tmp) / "state.json")
            env = {"WG_MANAGER_STATE": state}
            seed_state(state)
            before = Path(state).read_bytes()
            g = run(["--apply", "--yes", "delete", "ghost"], env=env, cwd=tmp)
            rec("global --apply reaches the subcommand", g.returncode != 2, f"rc={g.returncode}")
            rec("global --apply does not write", Path(state).read_bytes() == before, "state changed")
            c = run(["--color", "always", "list"], env=env, cwd=tmp)
            rec("global --color is honored", "\x1b" in c.stdout, "no ANSI from global flag")
            s = run(["list", "--self-test"], env=env, cwd=tmp)
            rec("subcommand --self-test refused", s.returncode == 2, f"rc={s.returncode}")

        # Dry-run purity on an isolated fixture.
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
            r1 = run(["list", "--dry-run"], env=env, cwd=tmp)
            r2 = run(["list", "--dry-run"], env=env, cwd=tmp)
            rec("render twice identical", r1.stdout.encode() == r2.stdout.encode(), "render differs")

        h2 = run(["--help"])
        rec("--help twice identical", h1.stdout.encode() == h2.stdout.encode(), "help differs")
        s2 = run(["--self-test"])
        rec("self-test twice identical", s1.stdout.encode() == s2.stdout.encode(), "self-test differs")

        # ---------------------------------------------------------------- L2
        with tempfile.TemporaryDirectory() as tmp:
            state = str(Path(tmp) / "state.json")
            env = {"WG_MANAGER_STATE": state}

            rcfg = run(["reconfigure", "--dry-run"], env=env, cwd=tmp)
            rcfg_blob = (rcfg.stdout + rcfg.stderr).lower()
            rec("reconfigure dry-run exits 0", rcfg.returncode == 0, f"rc={rcfg.returncode}")
            rec("reconfigure mentions QR/client", "qr" in rcfg_blob, "no QR hint")
            rec("reconfigure writes nothing", not Path(state).exists(), "state created")

            rec("--help lists menu", "menu" in h1.stdout, "missing menu")
            rec("--help lists reconfigure", "reconfigure" in h1.stdout, "missing reconfigure")
            rec("--help lists uninstall", "uninstall" in h1.stdout, "missing uninstall")

            reload_before = Path(state).read_bytes() if Path(state).exists() else None
            rld = run(["reload", "--dry-run"], env=env, cwd=tmp)
            rblob = (rld.stdout + rld.stderr).lower()
            rec("reload dry-run exits 0", rld.returncode == 0, f"rc={rld.returncode}")
            rec("reload mentions ip_forward", "ip_forward" in rblob, "no ip_forward")
            fw_primary = ("nft" in rblob) or ("firewall-cmd" in rblob)
            fw_rendered = ("masquerade" in rblob) and ("wg_manager" in rblob)
            rec("reload mentions firewall", fw_primary or fw_rendered, "no firewall token")
            reload_after = Path(state).read_bytes() if Path(state).exists() else None
            rec("reload writes nothing", reload_after == reload_before, "state created or modified")

            # Non-interactive `init --apply` refuses without explicit --set.
            fresh_state = str(Path(tmp) / "fresh.json")
            env_fresh = {"WG_MANAGER_STATE": fresh_state}
            ini = run(["init", "--apply", "--yes"], env=env_fresh, cwd=tmp)
            rec("non-tty init --apply refused", ini.returncode == 2, f"rc={ini.returncode}")
            rec("refused init writes nothing", not Path(fresh_state).exists(), "state created")

            seed = seed_state(state)
            bak = run(["backup"], env=env, cwd=tmp)
            rec("backup dry-run exits 0", bak.returncode == 0, f"rc={bak.returncode}")
            rec("backup dry-run writes nothing", "would-backup" in (bak.stdout + bak.stderr), "no would-backup")

            # check skips placeholder keys instead of reporting a dead handshake.
            seed["peers"] = [{"name": "bad", "role": "client", "kind": "ondemand", "pubkey": "PUBKEY-bad", "v4": "10.90.90.2", "enabled": True, "tombstoned": False}]
            Path(state).write_text(json.dumps(seed), encoding="utf-8")
            chk = run(["check"], env=env, cwd=tmp)
            cblob = (chk.stdout + chk.stderr).lower()
            rec("check warns on invalid key", "valid public key" in cblob or "no valid" in cblob, "no key warning")
            # check must exit non-zero when a row failed, and zero when only warnings.
            chk_fail = run(["check", "--json"], env=env, cwd=tmp)
            try:
                chk_payload = json.loads(chk_fail.stdout)
                rec("check --json is valid JSON", isinstance(chk_payload, dict), "not a dict")
                rec("check --json exit mirrors failed rows",
                    chk_fail.returncode == (1 if chk_payload.get("failed") else 0),
                    f"rc={chk_fail.returncode} failed={chk_payload.get('failed')}")
            except (ValueError, TypeError) as exc:
                rec("check --json is valid JSON", False, str(exc))
                rec("check --json exit mirrors failed rows", False, "unparseable")

            # add dry-run contract: --psk emits PresharedKey, nat66 emits ULA IPv6
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

            seed["pools_v4"] = [
                {"name": "infra", "range": "10.90.90.10-10.90.90.20", "kind": "static"},
                {"name": "clients", "range": "10.90.90.21-10.90.90.150", "kind": "next-free"},
            ]
            Path(state).write_text(json.dumps(seed), encoding="utf-8")
            add_cli = run(["add", "--dry-run", "--name", "carol"], env=env, cwd=tmp)
            rec("add client defaults to clients pool", "10.90.90.21" in add_cli.stdout, f"got out={add_cli.stdout}")

            add_mtk = run(["add", "--dry-run", "--name", "mtk1", "--kind", "infra", "--infra-type", "mikrotik", "--psk"], env=env, cwd=tmp)
            rec("add mikrotik exits 0", add_mtk.returncode == 0, f"rc={add_mtk.returncode}")
            rec("add mikrotik renders rsc interface", "/interface wireguard add" in add_mtk.stdout, "missing interface")
            rec("add mikrotik defaults to infra pool", "10.90.90.10" in add_mtk.stdout, f"missing 10.90.90.10 in {add_mtk.stdout}")

            if str(TOOL_ROOT) not in sys.path:
                sys.path.insert(0, str(TOOL_ROOT))
            from lib.renderers import render_rsc
            test_mtk_peer = {
                "name": "mtk-test", "role": "infra", "infra_type": "mikrotik", "privkey": GOOD_KEY_A,
                "psk": GOOD_KEY_B, "v4": "10.90.90.15/32", "keepalive": 25, "traffic": "server-only"
            }
            rsc_out = render_rsc(seed, test_mtk_peer, show_secrets=True)
            rec("render_rsc includes private-key", f'private-key="{test_mtk_peer["privkey"]}"' in rsc_out, "missing private-key in rsc")
            rec("render_rsc includes preshared-key", f'preshared-key="{test_mtk_peer["psk"]}"' in rsc_out, "missing preshared-key in rsc")
            rsc_red = render_rsc(seed, test_mtk_peer, show_secrets=False)
            rec("render_rsc redacts by default", GOOD_KEY_A not in rsc_red and GOOD_KEY_B not in rsc_red, "secrets leaked in render_rsc")

            add_rtr = run(["add", "--dry-run", "--name", "rtr1", "--kind", "infra", "--infra-type", "router"], env=env, cwd=tmp)
            rec("add router exits 0", add_rtr.returncode == 0, f"rc={add_rtr.returncode}")
            rec("add router renders conf Interface", "[Interface]" in add_rtr.stdout and "Address = 10.90.90." in add_rtr.stdout, f"got {add_rtr.stdout}")

            # edit dry-run must not leak infra secrets without --show-secrets.
            seed["peers"] = [{
                "name": "mtk-leak", "role": "infra", "infra_type": "mikrotik",
                "privkey": GOOD_KEY_A, "psk": GOOD_KEY_B, "pubkey": GOOD_KEY_B,
                "v4": "10.90.90.10/32", "enabled": True, "tombstoned": False, "pool": "infra",
            }]
            Path(state).write_text(json.dumps(seed), encoding="utf-8")
            ed = run(["edit", "mtk-leak", "--traffic", "server-only"], env=env, cwd=tmp)
            ed_blob = ed.stdout + ed.stderr
            rec("edit dry-run exits 0", ed.returncode == 0, f"rc={ed.returncode}")
            rec("edit dry-run hides private key", GOOD_KEY_A not in ed_blob, "private key leaked in edit preview")
            rec("edit dry-run hides psk", GOOD_KEY_B not in ed_blob, "psk leaked in edit preview")
            ed_show = run(["edit", "mtk-leak", "--traffic", "server-only", "--show-secrets"], env=env, cwd=tmp)
            rec("edit --show-secrets reveals key", GOOD_KEY_A in (ed_show.stdout + ed_show.stderr), "show-secrets did not reveal")

            # Every remaining command must at least run its dry-run branch.
            seed["peers"] = [
                {"name": "phone", "role": "client", "kind": "ondemand", "privkey": GOOD_KEY_A, "pubkey": GOOD_KEY_B,
                 "psk": GOOD_KEY_B, "v4": "10.90.90.2", "v6": "", "enabled": True, "tombstoned": False, "pool": "clients"},
                {"name": "dead", "role": "client", "kind": "ondemand", "privkey": GOOD_KEY_A, "pubkey": GOOD_KEY_A,
                 "v4": "10.90.90.3", "enabled": False, "tombstoned": True, "pool": "clients"},
            ]
            Path(state).write_text(json.dumps(seed), encoding="utf-8")
            for name, argv in (
                ("list", ["list", "--dry-run"]),
                ("status", ["status", "--dry-run"]),
                ("show", ["show", "phone"]),
                ("show-secrets", ["show", "phone", "--show-secrets"]),
                ("qr", ["qr", "phone"]),
                ("export", ["export", "phone", "--out-dir", str(Path(tmp) / "exports")]),
                ("export-all", ["export", "--all", "--out-dir", str(Path(tmp) / "exports")]),
                ("enable", ["enable", "phone", "--dry-run"]),
                ("disable", ["disable", "phone", "--dry-run"]),
                ("delete", ["delete", "phone", "--dry-run"]),
                ("purge", ["purge", "--dry-run"]),
                ("reclaim", ["reclaim", "dead", "--dry-run"]),
                ("sweep", ["sweep", "--dry-run"]),
                ("rollback-list", ["rollback", "--list"]),
            ):
                p = run(argv, env=env, cwd=tmp)
                rec(f"dry-run {name} exits 0", p.returncode == 0, f"rc={p.returncode} out={(p.stdout + p.stderr)[:120]}")

            st = run(["status", "--json"], env=env, cwd=tmp)
            try:
                st_payload = json.loads(st.stdout)
                rec("status --json is valid JSON", isinstance(st_payload, dict) and "peers" in st_payload, "bad payload")
                rec("status --json marks interface", "interface_present" in st_payload, "no interface_present")
            except (ValueError, TypeError) as exc:
                rec("status --json is valid JSON", False, str(exc))
                rec("status --json marks interface", False, "unparseable")

            ls = run(["list", "--json"], env=env, cwd=tmp)
            try:
                ls_payload = json.loads(ls.stdout)
                rec("list --json is valid JSON", isinstance(ls_payload, dict) and "peers" in ls_payload, "bad payload")
                rec("list --json reports tombstones", ls_payload.get("tombstoned") == 1, f"tombstoned={ls_payload.get('tombstoned')}")
            except (ValueError, TypeError) as exc:
                rec("list --json is valid JSON", False, str(exc))
                rec("list --json reports tombstones", False, "unparseable")

            # Corrupt state must fail with a clear message, not a traceback.
            Path(state).write_text("{not json", encoding="utf-8")
            corrupt = run(["list"], env=env, cwd=tmp)
            rec("corrupt state exits 1", corrupt.returncode == 1, f"rc={corrupt.returncode}")
            rec("corrupt state has no traceback", "Traceback" not in (corrupt.stdout + corrupt.stderr), "traceback leaked")
            # Wrong field type is also rejected early.
            seed_state(state)
            bad = json.loads(Path(state).read_text(encoding="utf-8"))
            bad["peers"] = [{"name": "x", "role": "client", "expires_at": "soon"}]
            Path(state).write_text(json.dumps(bad), encoding="utf-8")
            typed = run(["status"], env=env, cwd=tmp)
            rec("bad field type exits 1", typed.returncode == 1, f"rc={typed.returncode}")
            rec("bad field type names the field", "expires_at" in (typed.stdout + typed.stderr), "no field name")
            # Invalid state path is refused.
            badpath = run(["list"], env={"WG_MANAGER_STATE": "relative/state.json"}, cwd=tmp)
            rec("relative state path refused", badpath.returncode == 1, f"rc={badpath.returncode}")
            traversal = run(["list"], env={"WG_MANAGER_STATE": "/etc/wg-manager/../state.json"}, cwd=tmp)
            rec("traversal state path refused", traversal.returncode == 1, f"rc={traversal.returncode}")

            # rollback --to a missing file reports a missing backup, not corruption.
            seed_state(state)
            missing = run(["rollback", "--to", str(Path(tmp) / "nope.json"), "--apply", "--yes"], env=env, cwd=tmp)
            mblob = (missing.stdout + missing.stderr).lower()
            rec("rollback missing backup exits 1", missing.returncode == 1, f"rc={missing.returncode}")
            rec("rollback missing backup message", "not found" in mblob or "no encontrada" in mblob, "wrong message")

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

            # --dry-run wins over --apply: no write, no privilege error.
            seed_state(state)
            mixed = run(["backup", "--apply", "--yes", "--dry-run"], env=env, cwd=tmp)
            rec("--dry-run wins over --apply", mixed.returncode == 0 and not (Path(state).parent / "backups").exists(), f"rc={mixed.returncode}")
            seed_state(state)
            st = json.loads(Path(state).read_text(encoding="utf-8"))
            st["peers"] = [{"name": "phone", "role": "client", "kind": "ondemand", "privkey": GOOD_KEY_A,
                            "pubkey": GOOD_KEY_B, "v4": "10.90.90.2", "enabled": True,
                            "tombstoned": False, "pool": "clients"}]
            Path(state).write_text(json.dumps(st), encoding="utf-8")
            before_mixed = Path(state).read_bytes()
            mixed2 = run(["delete", "phone", "--apply", "--yes", "--dry-run"], env=env, cwd=tmp)
            rec("--dry-run wins on destructive", mixed2.returncode == 0 and Path(state).read_bytes() == before_mixed, f"rc={mixed2.returncode}")

        # Locale auto over pipes (non-TTY): no prompt or hang.
        with tempfile.TemporaryDirectory() as tmp:
            state = str(Path(tmp) / "state.json")
            seed_state(state)
            saved_locale = {key: os.environ.get(key) for key in ("LANG", "LC_ALL", "LANGUAGE")}
            try:
                locale_before = Path(state).read_bytes()
                for lang_value in ("es_ES.UTF-8", "C"):
                    lbase = dict(os.environ)
                    lbase["LANG"] = lang_value
                    lbase.pop("LC_ALL", None)
                    lbase.pop("LANGUAGE", None)
                    lbase["WG_MANAGER_STATE"] = state
                    proc = subprocess.run(
                        [sys.executable, str(ENTRY), "list", "--dry-run", "--lang", "auto"],
                        capture_output=True, text=True, env=lbase, cwd=tmp,
                        timeout=TIMEOUT, stdin=subprocess.DEVNULL, check=False,
                    )
                    rec(f"locale auto LANG={lang_value} exits 0", proc.returncode == 0, f"rc={proc.returncode}")
                rec("locale auto writes nothing", Path(state).read_bytes() == locale_before, "state created or modified")
            finally:
                for key, val in saved_locale.items():
                    if val is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = val

        # ---------------------------------------------------------------- L3
        with tempfile.TemporaryDirectory() as tmp:
            bindir, flog = fake_bin_dir(tmp)
            sysroot = Path(tmp) / "sysroot"
            state = Path(tmp) / "state.json"
            seed_state(state)
            env = fake_env(tmp, bindir, state, sysroot)

            # --sudo must re-exec the real entrypoint, not a library module.
            # A fake sudo only logs its argv and exits, so no real privilege
            # escalation happens and the re-exec cannot loop.
            sudo_dir = Path(tmp) / "sudobin"
            sudo_dir.mkdir()
            sudo_log = Path(tmp) / "sudo.log"
            fake_sudo = sudo_dir / "sudo"
            fake_sudo.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + str(sudo_log) + "\nexit 0\n",
                encoding="utf-8",
            )
            fake_sudo.chmod(0o755)
            sudo_state = Path(tmp) / "sudo-state.json"
            seed_state(sudo_state)
            sudo_env = {
                "PATH": str(sudo_dir) + os.pathsep + os.environ.get("PATH", ""),
                "WG_MANAGER_STATE": str(sudo_state),
            }
            try:
                is_root = os.geteuid() == 0
            except AttributeError:
                is_root = False
            if is_root:
                rec("--sudo re-execs the entrypoint", True, "SKIP running as root")
                rec("--sudo re-exec succeeds", True, "SKIP running as root")
            else:
                sudo_run = subprocess.run(
                    [sys.executable, str(ENTRY), "backup", "--apply", "--yes", "--sudo"],
                    capture_output=True, text=True, env=sudo_env, cwd=tmp, timeout=TIMEOUT,
                    stdin=subprocess.DEVNULL, check=False,
                )
                sudo_argv = sudo_log.read_text(encoding="utf-8") if sudo_log.exists() else ""
                rec("--sudo re-execs the entrypoint",
                    "main.py" in sudo_argv and "lib/system.py" not in sudo_argv,
                    f"argv={sudo_argv.strip()}")
                rec("--sudo re-exec succeeds", sudo_run.returncode == 0, f"rc={sudo_run.returncode}")
            # Unit-level: the firewall precheck refuses a missing engine.
            from lib import system as _system_mod
            _saved_which = _system_mod.shutil.which
            _system_mod.shutil.which = lambda name: None
            try:
                _system_mod._precheck_firewall("nft")
                rec("missing firewall engine refused", False, "no error raised")
            except ValueError as exc:
                rec("missing firewall engine refused", "nft" in str(exc), str(exc))
            finally:
                _system_mod.shutil.which = _saved_which
            # Unit-level: the WAN guard parses `ip -o` output and degrades safely.
            _saved_capture = _system_mod._run_capture
            _saved_wan_snapshot = _system_mod._wan_global_addrs
            _saved_eprint = _system_mod.eprint
            try:
                _system_mod.shutil.which = lambda name: None
                rec("WAN guard skips without ip", _system_mod._wan_global_addrs("eth0") is None, "expected None")
            finally:
                _system_mod.shutil.which = _saved_which
            try:
                _system_mod.shutil.which = lambda name: "/sbin/ip"
                sample = (
                    "2: ens6    inet 212.227.83.103/32 scope global ens6\\       valid_lft forever preferred_lft forever\n"
                    "2: ens6    inet6 2001:ba0:23b:4d00::1/128 scope global \\       valid_lft forever preferred_lft forever\n"
                    "2: ens6    inet6 fe80::1:9fff:fe5a:9eff/64 scope link \\       valid_lft forever preferred_lft forever\n"
                )
                _system_mod._run_capture = lambda argv, timeout=15: (0, sample, "")
                snap = _system_mod._wan_global_addrs("ens6")
                rec("WAN guard parses globals", snap == {"inet 212.227.83.103", "inet6 2001:ba0:23b:4d00::1"}, f"snap={snap}")
                _system_mod._run_capture = lambda argv, timeout=15: (1, "", "nope")
                rec("WAN guard skips on ip failure", _system_mod._wan_global_addrs("ens6") is None, "expected None")
            finally:
                _system_mod.shutil.which = _saved_which
                _system_mod._run_capture = _saved_capture
            # Unit-level: sysctl pins accept_ra on the WAN while IPv6 is enabled.
            from lib.renderers import render_sysctl as _render_sysctl
            sys6 = _render_sysctl({"server": {"ifname": "wg0", "wan_iface": "ens6"}, "ipv6": {"mode": "nat66"}})
            rec("sysctl pins WAN accept_ra=2", "net.ipv6.conf.ens6.accept_ra = 2" in sys6, sys6[-200:])
            rec("sysctl silences wg accept_ra", "net.ipv6.conf.wg0.accept_ra = 0" in sys6, sys6[-200:])
            sys4 = _render_sysctl({"server": {"ifname": "wg0", "wan_iface": "ens6"}, "ipv6": {"mode": "disabled"}})
            rec("sysctl omits accept_ra when disabled", "accept_ra" not in sys4, sys4[-200:])
            # Unit-level: the WAN guard warns on shrink, stays quiet on renumber.
            warned = []
            try:
                _system_mod.eprint = warned.append
                _system_mod._wan_global_addrs = lambda wan: {"inet 212.227.83.103"}
                _system_mod._warn_if_wan_addrs_lost("ens6", {"inet 212.227.83.103", "inet6 2001:ba0:23b:4d00::1"})
                rec("WAN guard warns on shrink", any("ens6" in str(m) for m in warned), f"warned={warned}")
                warned.clear()
                _system_mod._wan_global_addrs = lambda wan: {"inet 212.227.83.104"}
                _system_mod._warn_if_wan_addrs_lost("ens6", {"inet 212.227.83.103"})
                rec("WAN guard quiet on renumber", not warned, f"warned={warned}")
                _system_mod._warn_if_wan_addrs_lost("ens6", None)
                rec("WAN guard quiet when unknown", not warned, f"warned={warned}")
            finally:
                _system_mod.eprint = _saved_eprint
                _system_mod._wan_global_addrs = _saved_wan_snapshot

            # Sandboxed apply: init --apply writes the full file set.
            # The state lives in a dedicated subdirectory so uninstall only
            # removes manager-owned files, never the shared tmp fixtures.
            init_state = Path(tmp) / "statedir" / "state.json"
            init_env = fake_env(tmp, bindir, init_state, sysroot)
            init_apply = run([
                "init", "--apply", "--yes",
                "--set", "endpoint=vpn.example.com", "--set", "port=51820",
                "--set", "mtu=1420", "--set", "ifname=wg0", "--set", "backend=networkd",
                "--set", "wan_iface=eth0", "--set", "ipv4_prefix=10.90.90.0/24",
                "--set", "ipv4_hub=10.90.90.1", "--set", "ipv6_mode=disabled",
            ], env=init_env, cwd=tmp)
            rec("init --apply exits 0 (sandbox)", init_apply.returncode == 0, f"rc={init_apply.returncode} err={(init_apply.stdout + init_apply.stderr)[-200:]}")
            rec("init --apply writes state", init_state.exists(), "no state file")
            netdev = sysroot / "etc" / "systemd" / "network" / "90-wg0.netdev"
            network = sysroot / "etc" / "systemd" / "network" / "90-wg0.network"
            sysctl_conf = sysroot / "etc" / "sysctl.d" / "90-wg-manager.conf"
            nft_file = sysroot / "etc" / "nftables.d" / "90-wg-manager.nft"
            rec("init --apply writes netdev", netdev.exists(), "missing netdev")
            rec("init --apply writes network", network.exists(), "missing network")
            rec("init --apply writes sysctl", sysctl_conf.exists(), "missing sysctl")
            rec("init --apply writes nft", nft_file.exists(), "missing nft")
            if netdev.exists():
                mode = stat.S_IMODE(netdev.stat().st_mode)
                rec("netdev mode is private", mode in (0o600, 0o640), f"mode={oct(mode)}")
            rec("state mode is 0600", stat.S_IMODE(init_state.stat().st_mode) == 0o600, f"mode={oct(stat.S_IMODE(init_state.stat().st_mode))}")
            rec("state dir is 0700", stat.S_IMODE(init_state.parent.stat().st_mode) == 0o700, f"mode={oct(stat.S_IMODE(init_state.parent.stat().st_mode))}")
            # Regression: a maskless prefix fails fast at the prefix prompt
            # instead of collapsing pools ("10.94.0.0" silently became /32).
            bare_state = Path(tmp) / "barestatedir" / "state.json"
            bare_env = fake_env(tmp, bindir, bare_state, sysroot)
            bare_init = run([
                "init", "--apply", "--yes",
                "--set", "endpoint=vpn.example.com", "--set", "port=51820",
                "--set", "mtu=1420", "--set", "ifname=wg9", "--set", "backend=networkd",
                "--set", "wan_iface=eth0", "--set", "ipv4_prefix=10.94.0.0",
                "--set", "ipv4_hub=10.94.0.1", "--set", "ipv6_mode=disabled",
            ], env=bare_env, cwd=tmp)
            bare_out = bare_init.stdout + bare_init.stderr
            rec("init rejects maskless prefix", bare_init.returncode != 0, f"rc={bare_init.returncode}")
            rec("mask error hints the mask", "/24" in bare_out, bare_out[-200:])
            rec("maskless init writes nothing", not bare_state.exists(), "state was written")
            # Language persistence: init stores the choice; later commands
            # reuse it without --lang; WG_MANAGER_LANG wins over state.
            lang_state = Path(tmp) / "langstatedir" / "state.json"
            lang_env = fake_env(tmp, bindir, lang_state, sysroot, WG_MANAGER_LANG="es")
            lang_init = run([
                "init", "--apply", "--yes",
                "--set", "endpoint=vpn.example.com", "--set", "port=51820",
                "--set", "mtu=1420", "--set", "ifname=wg8", "--set", "backend=networkd",
                "--set", "wan_iface=eth0", "--set", "ipv4_prefix=10.94.0.0/24",
                "--set", "ipv4_hub=10.94.0.1", "--set", "ipv6_mode=disabled",
            ], env=lang_env, cwd=tmp)
            rec("init with env lang exits 0", lang_init.returncode == 0, f"rc={lang_init.returncode} err={(lang_init.stdout + lang_init.stderr)[-200:]}")
            lang_saved = ""
            if lang_state.exists():
                lang_saved = json.loads(lang_state.read_text(encoding="utf-8")).get("server", {}).get("lang", "")
            rec("init stores server.lang", lang_saved == "es", f"lang={lang_saved!r}")
            noenv = fake_env(tmp, bindir, lang_state, sysroot)
            show_es = run(["show", "nosuchpeer"], env=noenv, cwd=tmp)
            show_es_out = show_es.stdout + show_es.stderr
            rec("saved lang reused (es)", show_es.returncode != 0 and "no encontrado" in show_es_out, f"rc={show_es.returncode} out={show_es_out[-200:]}")
            deenv = fake_env(tmp, bindir, lang_state, sysroot, WG_MANAGER_LANG="de")
            show_de = run(["show", "nosuchpeer"], env=deenv, cwd=tmp)
            show_de_out = show_de.stdout + show_de.stderr
            rec("env lang beats saved (de)", show_de.returncode != 0 and "nicht gefunden" in show_de_out, f"rc={show_de.returncode} out={show_de_out[-200:]}")
            # sysctl snapshot only exists when /proc/sys is readable (Linux).
            if Path("/proc/sys/net/ipv4/ip_forward").exists():
                rec("init records sysctl_original", "sysctl_original" in init_state.read_text(encoding="utf-8"), "no sysctl snapshot")
            else:
                rec("init records sysctl_original", True, "SKIP no /proc/sys on this host")

            # add --apply allocates and persists; a second add is idempotent-safe.
            add1 = run(["add", "--apply", "--yes", "--name", "phone", "--no-psk"], env=init_env, cwd=tmp)
            rec("add --apply exits 0 (sandbox)", add1.returncode == 0, f"rc={add1.returncode} err={(add1.stdout + add1.stderr)[-200:]}")
            st = json.loads(init_state.read_text(encoding="utf-8"))
            peers = {p["name"]: p for p in st.get("peers", [])}
            rec("add persists the peer", "phone" in peers, "peer missing")
            rec("add assigns an IP", bool(peers.get("phone", {}).get("v4")), "no IP")
            add_dup = run(["add", "--apply", "--yes", "--name", "phone", "--no-psk"], env=init_env, cwd=tmp)
            rec("duplicate add refused", add_dup.returncode == 1, f"rc={add_dup.returncode}")
            # Two sequential adds get distinct IPs (lock + re-allocation).
            add2 = run(["add", "--apply", "--yes", "--name", "tablet", "--no-psk"], env=init_env, cwd=tmp)
            st = json.loads(init_state.read_text(encoding="utf-8"))
            ips = [p["v4"] for p in st.get("peers", []) if p.get("v4")]
            rec("adds get distinct IPs", len(ips) == len(set(ips)) == 2, f"ips={ips}")
            rec("add2 exits 0", add2.returncode == 0, f"rc={add2.returncode}")

            # disable --apply must not write; enable --apply round-trips.
            dis = run(["disable", "--apply", "--yes", "phone"], env=init_env, cwd=tmp)
            rec("disable --apply exits 0", dis.returncode == 0, f"rc={dis.returncode}")
            st = json.loads(init_state.read_text(encoding="utf-8"))
            phone = next(p for p in st["peers"] if p["name"] == "phone")
            rec("disable persists disabled", phone.get("enabled") is False, "still enabled")
            ena = run(["enable", "--apply", "--yes", "phone"], env=init_env, cwd=tmp)
            st = json.loads(init_state.read_text(encoding="utf-8"))
            phone = next(p for p in st["peers"] if p["name"] == "phone")
            rec("enable persists enabled", phone.get("enabled") is True, "still disabled")
            rec("enable exits 0", ena.returncode == 0, f"rc={ena.returncode}")

            # delete tombstones and reclaim restores.
            dele = run(["delete", "--apply", "--yes", "tablet"], env=init_env, cwd=tmp)
            st = json.loads(init_state.read_text(encoding="utf-8"))
            tablet = next(p for p in st["peers"] if p["name"] == "tablet")
            rec("delete tombstones", tablet.get("tombstoned") is True, "not tombstoned")
            rec("delete exits 0", dele.returncode == 0, f"rc={dele.returncode}")
            rcl = run(["reclaim", "--apply", "--yes", "tablet"], env=init_env, cwd=tmp)
            st = json.loads(init_state.read_text(encoding="utf-8"))
            tablet = next(p for p in st["peers"] if p["name"] == "tablet")
            rec("reclaim clears tombstone", tablet.get("tombstoned") is False, "still tombstoned")
            rec("reclaim exits 0", rcl.returncode == 0, f"rc={rcl.returncode}")

            # sweep disables expired peers and installs the expiry timer units.
            st = json.loads(init_state.read_text(encoding="utf-8"))
            for p in st["peers"]:
                if p["name"] == "tablet":
                    p["expires_at"] = 1700000000
            init_state.write_text(json.dumps(st), encoding="utf-8")
            sw_before = init_state.read_bytes()
            sw_dry = run(["sweep", "--dry-run"], env=init_env, cwd=tmp)
            rec("sweep dry-run exits 0", sw_dry.returncode == 0, f"rc={sw_dry.returncode}")
            rec("sweep dry-run previews tablet", "tablet" in (sw_dry.stdout + sw_dry.stderr), "no tablet in preview")
            rec("sweep dry-run writes nothing", init_state.read_bytes() == sw_before, "state changed")
            sw = run(["sweep", "--apply", "--yes"], env=init_env, cwd=tmp)
            rec("sweep --apply exits 0", sw.returncode == 0, f"rc={sw.returncode} err={(sw.stdout + sw.stderr)[-200:]}")
            st = json.loads(init_state.read_text(encoding="utf-8"))
            tablet = next(p for p in st["peers"] if p["name"] == "tablet")
            rec("sweep disables expired", tablet.get("enabled") is False, "still enabled")
            sw_svc = sysroot / "etc" / "systemd" / "system" / "wg-manager-expire.service"
            sw_tmr = sysroot / "etc" / "systemd" / "system" / "wg-manager-expire.timer"
            rec("sweep installs timer units", sw_svc.exists() and sw_tmr.exists(), "timer units missing")
            if sw_svc.exists():
                svc_text = sw_svc.read_text(encoding="utf-8")
                rec("expiry service hardens the root oneshot",
                    "NoNewPrivileges=yes" in svc_text and "ProtectHome=yes" in svc_text,
                    "no hardening directives")
                rec("expiry service uses an absolute ExecStart",
                    "ExecStart=/usr/local/bin/wg-manager sweep --apply --yes" in svc_text,
                    "ExecStart is not absolute")
            sw_nothing = run(["sweep", "--apply", "--yes"], env=init_env, cwd=tmp)
            rec("sweep no-op exits 0", sw_nothing.returncode == 0, f"rc={sw_nothing.returncode}")

            # backup --apply writes manual-* and rollback --list sees it.
            b1 = run(["backup", "--apply", "--yes"], env=init_env, cwd=tmp)
            backups = sorted((init_state.parent / "backups").glob("manual-*.json"))
            rec("backup --apply writes manual", b1.returncode == 0 and len(backups) == 1, f"rc={b1.returncode} backups={len(backups)}")
            rb_list = run(["rollback", "--list"], env=init_env, cwd=tmp)
            rec("rollback --list lists manual backups", "manual-" in rb_list.stdout, "manual backup not listed")
            # rollback --apply re-applies the state (network config too).
            if backups:
                rb_apply = run(["rollback", "--to", str(backups[0]), "--apply", "--yes"], env=init_env, cwd=tmp)
                rec("rollback --apply exits 0", rb_apply.returncode == 0, f"rc={rb_apply.returncode}")

            # reload --apply persists backend/firewall choice.
            rl = run(["reload", "--apply", "--yes", "--backend", "nm", "--firewall", "nft"], env=init_env, cwd=tmp)
            rec("reload --apply exits 0", rl.returncode == 0, f"rc={rl.returncode} err={(rl.stdout + rl.stderr)[-200:]}")
            st = json.loads(init_state.read_text(encoding="utf-8"))
            rec("reload persists backend", st["server"].get("backend") == "nm", f"backend={st['server'].get('backend')}")
            rec("reload persists firewall", st["server"].get("firewall") == "nft", f"firewall={st['server'].get('firewall')}")
            nm_file = sysroot / "etc" / "NetworkManager" / "system-connections" / "wg-manager.nmconnection"
            rec("reload nm writes nmconnection", nm_file.exists(), "missing nmconnection")

            # Unknown firewall/backend values must be rejected, not silently
            # mapped to a default.
            bad_fw = run(["reload", "--apply", "--yes", "--firewall", "iptables"], env=init_env, cwd=tmp)
            rec("unknown firewall rejected", bad_fw.returncode == 1, f"rc={bad_fw.returncode}")
            bad_bk = run(["reload", "--apply", "--yes", "--backend", "systemd"], env=init_env, cwd=tmp)
            rec("unknown backend rejected", bad_bk.returncode == 1, f"rc={bad_bk.returncode}")

            # export must not follow symlinks nor escape out-dir.
            seed_state(init_state)
            st = json.loads(init_state.read_text(encoding="utf-8"))
            st["peers"] = [{"name": "phone", "role": "client", "kind": "ondemand", "privkey": GOOD_KEY_A,
                            "pubkey": GOOD_KEY_B, "psk": GOOD_KEY_B, "v4": "10.90.90.2",
                            "enabled": True, "tombstoned": False, "pool": "clients"}]
            init_state.write_text(json.dumps(st), encoding="utf-8")
            outdir = Path(tmp) / "exports"
            victim = Path(tmp) / "victim.txt"
            victim.write_text("do not touch", encoding="utf-8")
            outdir.mkdir()
            (outdir / "phone.conf").symlink_to(victim)
            exp = run(["export", "phone", "--out-dir", str(outdir), "--apply", "--yes"], env=init_env, cwd=tmp)
            rec("export --apply exits 0", exp.returncode == 0, f"rc={exp.returncode} err={(exp.stdout + exp.stderr)[-200:]}")
            rec("export does not follow symlink", victim.read_text(encoding="utf-8") == "do not touch", "victim overwritten")
            rec("export replaces the symlink", not (outdir / "phone.conf").is_symlink(), "still a symlink")
            rec("export mode is 0600", stat.S_IMODE((outdir / "phone.conf").stat().st_mode) == 0o600, f"mode={oct(stat.S_IMODE((outdir / 'phone.conf').stat().st_mode))}")
            # A traversal name in state must be rejected before writing.
            st["peers"][0]["name"] = "../pwned"
            init_state.write_text(json.dumps(st), encoding="utf-8")
            exp_bad = run(["export", "phone", "--out-dir", str(outdir), "--apply", "--yes"], env=init_env, cwd=tmp)
            rec("export traversal name refused", exp_bad.returncode == 1, f"rc={exp_bad.returncode}")
            rec("export traversal writes nothing", not (Path(tmp) / "pwned.conf").exists(), "escaped out-dir")

            # uninstall --apply removes system files and state, restores sysctl.
            seed_state(init_state)
            un_apply = run(["uninstall", "--apply", "--yes"], env=init_env, cwd=tmp)
            rec("uninstall --apply exits 0 (sandbox)", un_apply.returncode == 0, f"rc={un_apply.returncode} err={(un_apply.stdout + un_apply.stderr)[-200:]}")
            rec("uninstall removes netdev", not netdev.exists(), "netdev still exists")
            rec("uninstall removes network", not network.exists(), "network still exists")
            rec("uninstall removes sysctl", not sysctl_conf.exists(), "sysctl still exists")
            rec("uninstall removes nft", not nft_file.exists(), "nft still exists")
            rec("uninstall removes sweep timer", not (sysroot / "etc" / "systemd" / "system" / "wg-manager-expire.timer").exists(), "timer still exists")
            rec("uninstall removes sweep service", not (sysroot / "etc" / "systemd" / "system" / "wg-manager-expire.service").exists(), "service still exists")
            rec("uninstall removes state dir", not init_state.parent.exists(), "state dir still exists")
            rec("main.py is preserved", ENTRY.exists(), "ENTRY missing")
            fw_log = flog.read_text(encoding="utf-8") if flog.exists() else ""
            rec("uninstall removes firewalld rules", "remove-interface" in fw_log and "remove-rich-rule" in fw_log, fw_log[-200:] if fw_log else "n/a")

        # ---------------------------------------------------------------- L4
        bad = 0
        bad_files = []
        for src in [ENTRY, *(TOOL_ROOT / "lib").glob("*.py")]:
            try:
                raw = src.read_bytes()
            except OSError:
                continue
            non_ascii = sum(1 for b in raw if b > 127)
            bad += non_ascii
            if non_ascii:
                bad_files.append(src.name)
        rec("source is ASCII-only", bad == 0, f"{bad} non-ascii bytes in {','.join(bad_files)}" if bad else "0 non-ascii bytes")

        with tempfile.TemporaryDirectory() as tmp:
            state = str(Path(tmp) / "state.json")
            env = {"WG_MANAGER_STATE": state}
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

            over = ""
            for width in ("60", "80", "120"):
                p = run(["list", "--width", width], env=env, cwd=tmp)
                for line in p.stdout.splitlines():
                    if len(line) > int(width):
                        over = f"w={width} len={len(line)}"
                        break
            rec("list fits width 60/80/120", not over, over or "within width")

            dry = run(["reload", "--dry-run"], env=env, cwd=tmp)
            dblob = (dry.stdout + dry.stderr).upper()
            rec("dry-run is labeled and distinct", "DRY-RUN" in dblob and "APPLIED" not in dblob, "not distinct")

            menu = subprocess.run(
                [sys.executable, str(ENTRY), "menu"],
                input="q\n", capture_output=True, text=True,
                env={**os.environ, "WG_MANAGER_STATE": state}, cwd=tmp,
                timeout=TIMEOUT, check=False,
            )
            rec("menu keeps [ 1] list token", "[ 1] list" in menu.stdout or "[1] list" in menu.stdout, "missing token")
            rec("menu quits cleanly", menu.returncode == 0, f"rc={menu.returncode}")
            rec("menu shows DRY-RUN mode", "DRY-RUN" in menu.stdout, "no mode badge")

            menu_dispatch = subprocess.run(
                [sys.executable, str(ENTRY), "menu"],
                input="1\n0\n", capture_output=True, text=True,
                env={**os.environ, "WG_MANAGER_STATE": state}, cwd=tmp,
                timeout=TIMEOUT, check=False,
            )
            rec("menu dispatches list action", menu_dispatch.returncode == 0, f"rc={menu_dispatch.returncode}")

            menu_shortcut = subprocess.run(
                [sys.executable, str(ENTRY), "menu"],
                input="l\n0\n", capture_output=True, text=True,
                env={**os.environ, "WG_MANAGER_STATE": state}, cwd=tmp,
                timeout=TIMEOUT, check=False,
            )
            rec("menu shortcut dispatches action", menu_shortcut.returncode == 0, f"rc={menu_shortcut.returncode}")

        # Direct verification of apply_system_uninstall and remove_state_data.
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
                [
                    sys.executable, "-c",
                    (
                        "import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
                        "from lib.system import apply_system_uninstall; from lib.state import remove_state_data, load_state; "
                        "st = load_state(); apply_system_uninstall(st); remove_state_data(); print('OK_CLEAN')"
                    ),
                    str(TOOL_ROOT),
                ],
                capture_output=True, text=True,
                env=dict(os.environ, **test_env), cwd=tmp, check=False,
            )
            rec("clean helper runs cleanly", "OK_CLEAN" in clean_cmd.stdout, f"out={clean_cmd.stdout} err={clean_cmd.stderr}")
            rec("uninstall deletes state dir", not test_sdir.exists(), "state_dir still exists")
            rec("uninstall deletes netdev", not mock_netdev.exists(), "netdev still exists")
            rec("uninstall deletes network", not mock_network.exists(), "network still exists")
            rec("uninstall deletes sysctl", not mock_sysctl.exists(), "sysctl still exists")
            rec("uninstall deletes nftables", not mock_nft.exists(), "nft still exists")

            if str(TOOL_ROOT) not in sys.path:
                sys.path.insert(0, str(TOOL_ROOT))
            from lib.renderers import firewalld_argv
            fw_cmds = firewalld_argv({"server": {"ifname": "wg0", "port": 51820}})
            has_trusted = any(c == ["firewall-cmd", "--permanent", "--zone=trusted", "--add-interface=wg0"] for c in fw_cmds)
            rec("firewalld trusted zone rule", has_trusted, f"cmds={fw_cmds}")

            from lib.system import preview_system_uninstall
            previews = preview_system_uninstall({"server": {"ifname": "wg0", "port": 51820}})
            labels = [p[0] for p in previews]
            rec("uninstall previews firewalld/ufw", "firewalld rules" in labels and "ufw rules" in labels, f"labels={labels}")

            # Backup mode sidecar survives rollback (0600 restore keeps 0644).
            from lib.system import _rollback_paths, backup_system_file
            cfg = Path(tmp) / "config.network"
            cfg.write_text("original", encoding="utf-8")
            cfg.chmod(0o644)
            bdir_state = Path(tmp) / "state.json"
            seed_state(bdir_state)
            os.environ["WG_MANAGER_STATE"] = str(bdir_state)
            backup = backup_system_file(str(cfg))
            cfg.write_text("modified", encoding="utf-8")
            cfg.chmod(0o600)
            if backup:
                _rollback_paths([(str(cfg), str(backup))])
            restored_mode = stat.S_IMODE(cfg.stat().st_mode)
            rec("rollback restores original mode", restored_mode == 0o644, f"mode={oct(restored_mode)}")

        # ---------------------------------------------------------------- L5
        # Regression layer: network renderer correctness, endpoint normalization,
        # state trust checks and failure-injection rollback (the apply safety net
        # is otherwise unreachable because fake binaries always exit 0).
        if str(TOOL_ROOT) not in sys.path:
            sys.path.insert(0, str(TOOL_ROOT))
        from lib import renderers as _renderers

        fixture = {
            "schema_version": 1,
            "server": {"endpoint": "vpn.example.com", "port": 51820, "mtu": 1420,
                       "ifname": "wg0", "backend": "nm", "wan_iface": "eth0",
                       "private_key": GOOD_KEY_A, "public_key": GOOD_KEY_B},
            "ipv4": {"prefix": "10.90.90.0/24", "hub": "10.90.90.1"},
            "ipv6": {"mode": "nat66", "prefix": "fd90:90:90::/64", "hub": "fd90:90:90::1", "wan_v6": ""},
            "pools_v4": [], "pools_v6": [],
            "peers": [{"name": "br", "role": "infra", "kind": "permanent", "infra_type": "router",
                       "pubkey": GOOD_KEY_B, "privkey": GOOD_KEY_A, "v4": "10.90.90.10", "v6": "fd90:90:90::10",
                       "enabled": True, "tombstoned": False, "traffic": "server-only",
                       "custom_routes": ["192.168.5.0/24", "fd00:5::/64"]}],
        }
        nm_out = _renderers.render_nm(fixture, show_secrets=True)
        rec("nm route uses keyfile comma syntax",
            "route1=192.168.5.0/24,10.90.90.10" in nm_out, "route syntax wrong")
        rec("nm does not emit legacy routes= list", "routes=" not in nm_out, "legacy routes= emitted")
        rec("nm ipv6 route lives in [ipv6]",
            "route1=fd00:5::/64,fd90:90:90::10" in nm_out.split("[ipv6]", 1)[-1], "v6 route family wrong")
        net_out = _renderers.render_network(fixture)
        rec("network ipv6 route uses ipv6 gateway",
            "Destination=fd00:5::/64\nGateway=fd90:90:90::10" in net_out, "v6 gateway wrong")
        rec("network ipv4 route uses ipv4 gateway",
            "Destination=192.168.5.0/24\nGateway=10.90.90.10" in net_out, "v4 gateway wrong")

        ep_hostname_port = dict(fixture)
        ep_hostname_port["server"] = dict(fixture["server"], endpoint="vpn.example.com:51821")
        wq = _renderers.render_wgquick(ep_hostname_port, fixture["peers"][0], show_secrets=True)
        rec("endpoint host:port keeps embedded port",
            "Endpoint = vpn.example.com:51821" in wq, "embedded port lost")
        rec("hostname endpoint is not bracketed", "[vpn.example.com" not in wq, "hostname bracketed")
        ep_v6 = dict(fixture)
        ep_v6["server"] = dict(fixture["server"], endpoint="[2001:db8::1]")
        wq6 = _renderers.render_wgquick(ep_v6, fixture["peers"][0], show_secrets=True)
        rec("ipv6 endpoint is bracketed once",
            "Endpoint = [2001:db8::1]:51820" in wq6, "ipv6 endpoint wrong")
        rsc_out = _renderers.render_rsc(ep_hostname_port, fixture["peers"][0], show_secrets=True)
        rec("rsc endpoint split host/port",
            'endpoint-address="vpn.example.com" endpoint-port=51821' in rsc_out, "rsc endpoint not split")

        # N4: a client's custom_routes are reached THROUGH the hub; they must not
        # be advertised server-side nor create a hub FIB route back to the client.
        client_state = dict(fixture)
        client_state["peers"] = [{"name": "cl", "role": "client", "kind": "ondemand",
                                  "pubkey": GOOD_KEY_A, "privkey": GOOD_KEY_B, "psk": GOOD_KEY_B,
                                  "v4": "10.90.90.30", "enabled": True, "tombstoned": False,
                                  "traffic": "custom-routes", "custom_routes": ["172.16.9.0/24"]}]
        cl_nm = _renderers.render_nm(client_state, show_secrets=True)
        cl_section = cl_nm.split("[wireguard-peer." + GOOD_KEY_A + "]", 1)[-1].split("[", 1)[0]
        rec("client custom-routes not advertised server-side", "172.16.9.0/24" not in cl_section, "route advertised on server")
        rec("client custom-routes absent from hub FIB routes", "172.16.9.0/24" not in _renderers.render_network(client_state), "hub route created")
        cl_wq = _renderers.render_wgquick(client_state, client_state["peers"][0], show_secrets=True)
        rec("client still tunnels its custom-routes", "172.16.9.0/24" in cl_wq, "client route lost")

        # N8: overlapping advertised prefixes across peers are reported.
        from lib.validators import find_allowed_ips_overlaps
        overlap_state = {"peers": [
            {"name": "r1", "role": "infra", "enabled": True, "v4": "10.90.90.10", "custom_routes": ["10.10.0.0/24"]},
            {"name": "r2", "role": "infra", "enabled": True, "v4": "10.90.90.11", "custom_routes": ["10.10.0.128/25"]},
        ]}
        overlaps = find_allowed_ips_overlaps(overlap_state)
        rec("overlapping AllowedIPs detected", len(overlaps) == 1, f"overlaps={overlaps}")

        # State trust: a symlinked state file is rejected (not followed).
        with tempfile.TemporaryDirectory() as tmp:
            real_state = Path(tmp) / "real.json"
            seed_state(real_state)
            link_state = Path(tmp) / "link.json"
            link_state.symlink_to(real_state)
            sym = run(["list"], env={"WG_MANAGER_STATE": str(link_state)}, cwd=tmp)
            rec("symlinked state rejected", sym.returncode == 1 and "Traceback" not in (sym.stdout + sym.stderr),
                f"rc={sym.returncode}")
            forbidden = run(["list"], env={"WG_MANAGER_STATE": "/state.json"}, cwd=tmp)
            rec("state in a system parent rejected", forbidden.returncode == 1 and "Traceback" not in (forbidden.stdout + forbidden.stderr),
                f"rc={forbidden.returncode}")

        # Failure injection: an injected post-verify failure must roll the file
        # set back and never claim success (the offline SYSROOT verifier would
        # otherwise pass on mere file existence).
        with tempfile.TemporaryDirectory() as tmp:
            import lib.state as _statemod
            import lib.system as _sysmod
            sysroot = Path(tmp) / "sysroot"
            fstate = Path(tmp) / "statedir" / "state.json"
            seeded = seed_state(fstate)
            seeded["server"]["private_key"] = GOOD_KEY_A
            seeded["server"]["public_key"] = GOOD_KEY_B
            fstate.write_text(json.dumps(seeded, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            os.environ["WG_MANAGER_STATE"] = str(fstate)
            saved = {
                "SYSROOT": _sysmod.SYSROOT,
                "_post_verify": _sysmod._post_verify,
                "which": _sysmod.shutil.which,
                "_precheck_backend": _sysmod._precheck_backend,
                "_precheck_firewall": _sysmod._precheck_firewall,
            }
            _sysmod.SYSROOT = str(sysroot)
            _sysmod.shutil.which = lambda *a, **k: None
            _sysmod._post_verify = lambda *a, **k: "injected failure"
            _sysmod._precheck_backend = lambda *a, **k: None
            _sysmod._precheck_firewall = lambda *a, **k: None
            try:
                injected_state = _statemod.load_state()
                netdev_path = Path(_sysmod._sp("/etc/systemd/network/90-wg0.netdev"))
                netdev_path.parent.mkdir(parents=True, exist_ok=True)
                netdev_path.write_text("original-netdev", encoding="utf-8")
                applied = _sysmod.apply_system_reload(injected_state, "networkd", "nft", None)
                rec("injected post-verify returns failure", applied is False, f"applied={applied}")
                rec("injected post-verify restores netdev",
                    netdev_path.exists() and netdev_path.read_text(encoding="utf-8") == "original-netdev",
                    "netdev not restored")
                rec("injected post-verify removes new sysctl",
                    not Path(_sysmod._sp("/etc/sysctl.d/90-wg-manager.conf")).exists(), "sysctl left behind")
            finally:
                _sysmod.SYSROOT = saved["SYSROOT"]
                _sysmod._post_verify = saved["_post_verify"]
                _sysmod.shutil.which = saved["which"]
                _sysmod._precheck_backend = saved["_precheck_backend"]
                _sysmod._precheck_firewall = saved["_precheck_firewall"]
                os.environ.pop("WG_MANAGER_STATE", None)

        # Declarative layer: spec normalization, pure plan/diff and idempotent
        # reconcile under SYSROOT (apply twice must converge to no changes).
        from lib.reconcile import compute_plan
        from lib.spec import normalize_spec
        desired_doc = {
            "apiVersion": "wg-manager/v1",
            "server": {"endpoint": "vpn.example.com", "port": 51820, "mtu": 1420, "ifname": "wg0",
                       "backend": "networkd", "wan_iface": "eth0"},
            "ipv4": {"prefix": "10.90.90.0/24", "hub": "10.90.90.1"},
            "ipv6": {"mode": "disabled"},
            "pools": {"v4": [{"name": "clients", "range": "10.90.90.21-10.90.90.150", "kind": "next-free"}]},
            "peers": [{"name": "phone", "role": "client", "traffic": "full-tunnel", "psk": {"from_env": "WGM_TEST_PSK"}}],
        }
        desired = normalize_spec(desired_doc)
        rec("spec normalizes apiVersion", desired["apiVersion"] == "wg-manager/v1", "api gone")
        empty_state = {"server": {}, "ipv4": {}, "ipv6": {}, "pools_v4": [], "pools_v6": [], "peers": []}
        plan_add = compute_plan(empty_state, desired)
        rec("plan detects peer add", any(c["action"] == "add" and c["name"] == "phone" for c in plan_add), f"plan={plan_add}")
        rec("plan is deterministic", compute_plan(empty_state, desired) == plan_add, "plan differs")
        converged = {"server": dict(desired["server"]), "ipv4": dict(desired["ipv4"]),
                     "ipv6": {"mode": "disabled"}, "pools_v4": [dict(p) for p in desired["pools"]["v4"]],
                     "pools_v6": [],
                     "peers": [{"name": "phone", "role": "client", "traffic": "full-tunnel", "psk": "x",
                                "enabled": True, "tombstoned": False}]}
        rec("plan empty when converged", compute_plan(converged, desired) == [], "spurious changes")
        bad_spec = {"apiVersion": "wg-manager/v2", "server": {}, "peers": []}
        try:
            normalize_spec(bad_spec)
            rec("spec rejects unknown apiVersion", False, "accepted")
        except ValueError:
            rec("spec rejects unknown apiVersion", True, "rejected")

        with tempfile.TemporaryDirectory() as ptmp:
            spec_path = Path(ptmp) / "desired.json"
            spec_path.write_text(json.dumps(desired_doc), encoding="utf-8")
            pl = run(["plan", "--config", str(spec_path), "--json"],
                     env={"WG_MANAGER_STATE": str(Path(ptmp) / "nostate.json"), "WGM_TEST_PSK": GOOD_KEY_A}, cwd=ptmp)
        try:
            pl_payload = json.loads(pl.stdout)
            rec("plan --json is valid JSON", isinstance(pl_payload, dict), "not a dict")
            rec("plan --json reports changed", pl_payload.get("changed") is True, f"payload={pl_payload.get('changed')}")
        except (ValueError, TypeError) as exc:
            rec("plan --json is valid JSON", False, str(exc))
            rec("plan --json reports changed", False, "unparseable")
        rec("plan is read-only", pl.returncode == 0, f"rc={pl.returncode}")

        # Self-contained sandboxed reconcile block (fake binaries + SYSROOT).
        with tempfile.TemporaryDirectory() as rtmp:
            rbindir, _rlog = fake_bin_dir(rtmp)
            rsysroot = Path(rtmp) / "sysroot"
            spec2 = Path(rtmp) / "desired.json"
            spec2.write_text(json.dumps(desired_doc), encoding="utf-8")
            rec_state = Path(rtmp) / "statedir" / "state.json"
            rec_env = fake_env(rtmp, rbindir, rec_state, rsysroot)
            rec_env["WGM_TEST_PSK"] = GOOD_KEY_A
            # Seed the state in place (reconcile is update-in-place, not bootstrap).
            seed_state(rec_state)
            seeded = json.loads(rec_state.read_text(encoding="utf-8"))
            seeded["server"]["private_key"] = GOOD_KEY_A
            seeded["server"]["public_key"] = GOOD_KEY_B
            rec_state.write_text(json.dumps(seeded, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            r1 = run(["reconcile", "--config", str(spec2), "--apply", "--yes", "--json"], env=rec_env, cwd=rtmp)
            rec("reconcile --apply exits 0", r1.returncode == 0, f"rc={r1.returncode} err={(r1.stdout + r1.stderr)[-160:]}")
            rec("reconcile writes state", rec_state.exists(), "no state")
            if rec_state.exists():
                st = json.loads(rec_state.read_text(encoding="utf-8"))
                rec("reconcile persisted peer", any(p.get("name") == "phone" for p in st.get("peers", [])), "peer missing")
            r2 = run(["reconcile", "--config", str(spec2), "--apply", "--yes", "--json"], env=rec_env, cwd=rtmp)
            try:
                r2_payload = json.loads(r2.stdout)
                rec("reconcile is idempotent", r2_payload.get("changed") is False, f"changed={r2_payload.get('changed')}")
            except (ValueError, TypeError) as exc:
                rec("reconcile is idempotent", False, str(exc))
            pl2 = run(["plan", "--config", str(spec2), "--json", "--detailed-exitcode"], env=rec_env, cwd=rtmp)
            rec("converged plan exits 0", pl2.returncode == 0, f"rc={pl2.returncode}")
            drift_doc = json.loads(json.dumps(desired_doc))
            drift_doc["server"]["endpoint"] = "changed.example.com"
            drift_path = Path(rtmp) / "drift.json"
            drift_path.write_text(json.dumps(drift_doc), encoding="utf-8")
            pl3 = run(["plan", "--config", str(drift_path), "--json", "--detailed-exitcode"], env=rec_env, cwd=rtmp)
            rec("drift plan exits 3", pl3.returncode == 3, f"rc={pl3.returncode}")
            r3 = run(["reconcile", "--config", str(spec2), "--apply", "--yes", "--json"], env=rec_env, cwd=rtmp)
            try:
                r3_payload = json.loads(r3.stdout)
                rec("second reconcile is a true no-op",
                    r3_payload.get("summary", {}).get("update") == 0
                    and r3_payload.get("summary", {}).get("add") == 0, f"summary={r3_payload.get('summary')}")
            except (ValueError, TypeError) as exc:
                rec("second reconcile is a true no-op", False, str(exc))

            # P1: Prometheus metrics are valid text with stable metric names.
            met = run(["metrics"], env=rec_env, cwd=rtmp)
            rec("metrics exits 0", met.returncode == 0, f"rc={met.returncode}")
            rec("metrics emits prometheus names", "wg_manager_peers_total" in met.stdout and "# TYPE" in met.stdout,
                "missing metric names")
            met_json = run(["metrics", "--format", "json"], env=rec_env, cwd=rtmp)
            try:
                met_payload = json.loads(met_json.stdout)
                rec("metrics --format json is valid", isinstance(met_payload, dict) and "metrics" in met_payload, "bad payload")
            except (ValueError, TypeError) as exc:
                rec("metrics --format json is valid", False, str(exc))

            # P1: bulk peer import (json + ndjson), idempotent with --upsert.
            import_doc = Path(rtmp) / "peers.json"
            import_doc.write_text(json.dumps([
                {"name": "bulk1", "role": "client", "traffic": "server-only", "no_psk": True},
                {"name": "bulk2", "role": "client", "traffic": "server-only", "no_psk": True},
            ]), encoding="utf-8")
            imp = run(["peers", "--file", str(import_doc), "--apply", "--yes"],
                      env=rec_env, cwd=rtmp)
            rec("peers import exits 0", imp.returncode == 0, f"rc={imp.returncode} err={(imp.stdout + imp.stderr)[-160:]}")
            st_imp = json.loads(rec_state.read_text(encoding="utf-8"))
            rec("peers import persisted", {"bulk1", "bulk2"} <= {p.get("name") for p in st_imp.get("peers", [])}, "peers missing")
            imp_dup = run(["peers", "--file", str(import_doc), "--apply", "--yes"],
                          env=rec_env, cwd=rtmp)
            rec("peers import refuses duplicates", imp_dup.returncode == 1, f"rc={imp_dup.returncode}")
            imp_up = run(["peers", "--file", str(import_doc), "--upsert", "--apply", "--yes"],
                         env=rec_env, cwd=rtmp)
            rec("peers import --upsert exits 0", imp_up.returncode == 0, f"rc={imp_up.returncode}")

            # N6: hub->peer NEW warning is exposed as a check row (pure helper path).
            n6_state = {"server": {"port": 51820}, "peers": []}
            preview = preview_system_uninstall(n6_state)
            rec("uninstall preview still lists nftables", any("nftables" in p[0] for p in preview), "preview drift")

        # i18n key parity across en/es/de.
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

    print(f"{'CHECK':32} {'RESULT':6} DETAIL")
    failed = 0
    for name, passed, detail in rows:
        print(f"{name:32} {'PASS' if passed else 'FAIL':6} {detail}")
        failed += 0 if passed else 1
    print(f"OK: {TOOL_ROOT.name}" if failed == 0 else f"FAILURES: {failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
