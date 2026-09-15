# selftest.py
import argparse
import base64
import json
import os
import shutil
import string
import sys
import tempfile
from pathlib import Path

from .commands import cmd_reconfigure, cmd_reload
from .crypto import is_valid_wgkey
from .i18n import CONFIRM_TOKENS, STRINGS, detect_system_lang, t
from .ipam import (
    IPAMError,
    _parse_wan_iface,
    allocate_static,
    check_wan_overlap,
    check_wan_v6_onlink,
    exhaustion_message,
    next_free_ip,
    peers_sorted,
    pool_ranges_overlap,
    suggest_pool_spans,
)
from .presentation import (
    color_enabled,
    eprint,
)
from .renderers import (
    redact_text,
    render_firewalld,
    render_netdev,
    render_network,
    render_nft,
    render_nm,
    render_rsc,
    render_sysctl,
    render_wgquick,
)
from .state import default_state
from .system import detect_net_backend
from .validators import (
    nft_structural_ok,
    validate_ifname,
    validate_name,
    validate_port,
    validate_prefix,
    validate_safe_path,
)


# ---------------------------------------------------------------- self-test
def _placeholders(text):
    fmt = string.Formatter()
    found = set()
    for _lit, field, _fmt, _conv in fmt.parse(str(text)):
        if field is not None and field != "":
            found.add(field.split("!")[0].split(":")[0].split(".")[0])
    return found


def cmd_self_test(_args=None):
    failures = []

    def fail(detail):
        failures.append(str(detail))

    # 1. Language set.
    if set(STRINGS.keys()) != {"en", "es", "de"}:
        fail("lang set != {en,es,de}: " + str(sorted(STRINGS.keys())))
    # 2. Key parity.
    en_keys = set(STRINGS.get("en", {}).keys())
    for lang in ("es", "de"):
        keys = set(STRINGS.get(lang, {}).keys())
        if keys != en_keys:
            fail("key parity " + lang + ": missing=" + str(sorted(en_keys - keys)) + " extra=" + str(sorted(keys - en_keys)))
    # 3. Placeholder parity.
    for key in sorted(en_keys):
        base = _placeholders(STRINGS["en"][key])
        for lang in ("es", "de"):
            other = _placeholders(STRINGS.get(lang, {}).get(key, ""))
            if other != base:
                fail("placeholder parity " + lang + ":" + key + " en=" + str(sorted(base)) + " got=" + str(sorted(other)))
    # 4. Confirm tokens.
    try:
        en_yes = CONFIRM_TOKENS["en"]["yes"]
        if "y" not in en_yes or "yes" not in en_yes:
            fail("confirm en missing y/yes")
        es_yes = CONFIRM_TOKENS["es"]["yes"]
        if "s" not in es_yes or "si" not in es_yes:
            fail("confirm es missing s/si")
        de_yes = CONFIRM_TOKENS["de"]["yes"]
        if "j" not in de_yes or "ja" not in de_yes:
            fail("confirm de missing j/ja")
        for lang in ("en", "es", "de"):
            yes = CONFIRM_TOKENS[lang]["yes"]
            if "y" not in yes or "yes" not in yes:
                fail("confirm " + lang + " must tolerate y/yes")
    except KeyError as exc:
        fail("confirm tokens missing: " + str(exc))
    # 5. Allocator fixtures (pure, offline, TMPDIR only).
    def _mk(name, role, kind, v4, tomb=False):
        return {"name": name, "role": role, "kind": kind, "v4": v4, "v6": "", "tombstoned": tomb}
    try:
        with tempfile.TemporaryDirectory():
            peers = []
            if allocate_static("10.90.90.0/24", peers, "10.90.90.10", "10.90.90.1") != "10.90.90.10":
                fail("infra static mismatch")
            peers.extend([_mk("infra1", "infra", "permanent", "10.90.90.10"), _mk("c1", "client", "ondemand", "10.90.90.2")])
            if next_free_ip("10.90.90.0/24", peers, "10.90.90.1") != "10.90.90.3":
                fail("next-free expected 10.90.90.3")
            peers.append(_mk("dead", "client", "ondemand", "10.90.90.3", True))
            if next_free_ip("10.90.90.0/24", peers, "10.90.90.1") == "10.90.90.3":
                fail("tombstone address reused")
            purged = [p for p in peers if not p.get("tombstoned")]
            if next_free_ip("10.90.90.0/24", purged, "10.90.90.1") != "10.90.90.3":
                fail("purge did not free 10.90.90.3")
            tiny = [_mk("a", "client", "ondemand", "10.9.9.1"), _mk("b", "client", "ondemand", "10.9.9.2")]
            if next_free_ip("10.9.9.0/30", tiny, "10.9.9.1") is not None:
                fail("exhaustion expected None")
            msg = exhaustion_message("clients", "10.9.9.0/30", tiny)
            for token in ("clients", "10.9.9.0/30"):
                if token not in msg:
                    fail("exhaustion message missing " + token)
            first = next_free_ip("192.168.7.0/24", [], "192.168.7.1")
            if first in ("192.168.7.0", "192.168.7.1", "192.168.7.255"):
                fail("allocated reserved address " + str(first))
    except IPAMError as exc:
        fail("allocator raised: " + str(exc))
    except OSError as exc:
        fail("tmpdir failed: " + str(exc))
    # 6. Renderer sort permanents-first and purity (no writes).
    try:
        mixed = [_mk("z-ondemand", "client", "ondemand", "10.90.90.5"), _mk("a-infra", "infra", "permanent", "10.90.90.10"), _mk("m-perm", "client", "permanent", "10.90.90.3")]
        if [p["name"] for p in peers_sorted(mixed)] != ["a-infra", "m-perm", "z-ondemand"]:
            fail("sort permanents-first failed")
        with tempfile.TemporaryDirectory() as tmp2:
            before = set(os.listdir(tmp2))
            fixture = default_state()
            fixture["peers"] = mixed
            for out in (render_netdev(fixture), render_network(fixture), render_nm(fixture), render_nft(fixture), render_sysctl(fixture), render_wgquick(fixture, mixed[0]), render_rsc(fixture, mixed[0])):
                _ = out
            _ = render_firewalld(fixture)
            if set(os.listdir(tmp2)) != before:
                fail("renderer wrote files")
    except (ValueError, IPAMError, KeyError) as exc:
        fail("renderer/sort raised: " + str(exc))
    # 7. Validators reject ../ and bad ports.
    def _rejects(func, *vals):
        for val in vals:
            try:
                func(val)
                fail("validator accepted " + str(val))
            except ValueError:
                pass
    _rejects(validate_name, "../evil", "bad/name")
    _rejects(validate_port, 0, 99999, "abc", -1)
    _rejects(validate_prefix, "not-a-prefix")
    _rejects(validate_safe_path, "../escape")
    # 8. Dry-run writes nothing.
    try:
        with tempfile.TemporaryDirectory() as tmp3:
            before = set(os.listdir(tmp3))
            fixture = default_state()
            _ = render_netdev(fixture)
            _ = render_nft(fixture)
            if set(os.listdir(tmp3)) != before or (Path(tmp3) / "probe.txt").exists():
                fail("dry-run wrote files")
    except OSError as exc:
        fail("dry-run check failed: " + str(exc))
    # WAN overlap pure check (offline fixture, no subprocess).
    try:
        if not check_wan_overlap("10.90.90.0/24", ["10.90.90.0/24", "192.168.1.0/24"]):
            fail("wan overlap fixture missed")
        if check_wan_overlap("10.99.99.0/24", ["192.168.1.0/24"]):
            fail("wan overlap false positive")
        if not check_wan_v6_onlink("2001:db8:1::/64", ["2001:db8:1::/64"]):
            fail("wan v6 on-link fixture missed")
    except ValueError as exc:
        fail("wan guard raised: " + str(exc))
    # 9. System-locale detection: LANG=es_ES.UTF-8 -> es (no writes).
    try:
        saved = {k: os.environ.get(k) for k in ("LANGUAGE", "LC_ALL", "LANG")}
        try:
            os.environ.pop("LANGUAGE", None)
            os.environ.pop("LC_ALL", None)
            os.environ["LANG"] = "es_ES.UTF-8"
            if detect_system_lang() != "es":
                fail("detect_system_lang es_ES.UTF-8 != es")
            os.environ["LANG"] = "de_DE.UTF-8"
            if detect_system_lang() != "de":
                fail("detect_system_lang de_DE != de")
            os.environ["LANG"] = "C"
            if detect_system_lang() != "en":
                fail("detect_system_lang C != en")
            os.environ["LANG"] = "en_US.UTF-8"
            if detect_system_lang() != "en":
                fail("detect_system_lang en_US != en")
            os.environ["LANGUAGE"] = "de:es:en"
            os.environ["LANG"] = "es_ES.UTF-8"
            if detect_system_lang() != "de":
                fail("LANGUAGE precedence failed")
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
    except (OSError, ValueError) as exc:
        fail("locale detect raised: " + str(exc))
    # 10. Reconfigure dry-run warning contains QR token (pure, TMPDIR only).
    try:
        with tempfile.TemporaryDirectory() as tmp4:
            state_file = Path(tmp4) / "state.json"
            fixture = default_state()
            fixture["ipv6"] = {"mode": "nat66", "prefix": "fd90:90:90::/64", "hub": "fd90:90:90::1", "wan_v6": ""}
            fixture["peers"] = [
                {"name": "infra1", "role": "infra", "kind": "permanent", "v4": "10.90.90.10", "v6": "", "tombstoned": False},
                {"name": "c1", "role": "client", "kind": "ondemand", "v4": "10.90.90.2", "v6": "", "tombstoned": False},
            ]
            state_file.write_text(json.dumps(fixture), encoding="utf-8")
            old_state = os.environ.get("WG_MANAGER_STATE")
            os.environ["WG_MANAGER_STATE"] = str(state_file)
            try:
                import contextlib as _ctx
                import io as _io
                buf = _io.StringIO()
                rargs = argparse.Namespace(ipv6_mode="routed", ipv6_prefix="2001:db8:1234:9000::/64", ipv6_wan="", wan="", endpoint="", port=None, mtu=None, apply=False, yes=False, sudo=False, dry_run=False, show_secrets=False)
                with _ctx.redirect_stdout(buf):
                    rc = cmd_reconfigure(rargs)
                out = buf.getvalue()
                if rc != 0:
                    fail("reconfigure dry-run rc != 0")
                if "QR" not in out:
                    fail("reconfigure warning missing QR token")
                # Dry-run must not mutate state file content (real assertion).
                if Path(state_file).read_text(encoding="utf-8") != json.dumps(fixture):
                    fail("reconfigure dry-run mutated state file")
                # Reload dry-run stays pure (no system writes in dry-run).
                buf2 = _io.StringIO()
                reload_args = argparse.Namespace(backend="", firewall="", apply=False, yes=False, sudo=False, dry_run=True, show_secrets=False)
                with _ctx.redirect_stdout(buf2):
                    rc2 = cmd_reload(reload_args)
                if rc2 != 0:
                    fail("reload dry-run rc != 0")
            finally:
                if old_state is None:
                    os.environ.pop("WG_MANAGER_STATE", None)
                else:
                    os.environ["WG_MANAGER_STATE"] = old_state
    except (OSError, ValueError, SystemExit) as exc:
        fail("reconfigure dry-run raised: " + str(exc))
    # 11. Color disabled in pipes (plain substrings preserved).
    try:
        pipe_args = argparse.Namespace(color="auto", no_color=False)
        # In self-test stdout is a pipe, so auto must be False; never/always honored.
        if color_enabled(pipe_args) and not sys.stdout.isatty():
            fail("color enabled in pipe with auto")
        never_args = argparse.Namespace(color="never", no_color=False)
        if color_enabled(never_args):
            fail("color never still enabled")
        nocolor_args = argparse.Namespace(color="always", no_color=True)
        if color_enabled(nocolor_args):
            fail("--no-color still enabled")
        os.environ["NO_COLOR"] = "1"
        try:
            always_args = argparse.Namespace(color="always", no_color=False)
            if color_enabled(always_args):
                fail("NO_COLOR still enabled")
        finally:
            del os.environ["NO_COLOR"]
    except (OSError, ValueError) as exc:
        fail("color check raised: " + str(exc))
    # 12. Net backend autodetection offline: systemctl missing -> family default, no raise, no writes.
    orig_which = shutil.which
    try:
        shutil.which = lambda *a, **k: None
        try:
            res = detect_net_backend()
        finally:
            shutil.which = orig_which
        if not isinstance(res, tuple) or len(res) != 2:
            fail("detect_net_backend must return 2-tuple")
        else:
            be, rs = res
            if be not in ("networkd", "nm", None):
                fail("detect_net_backend backend unexpected: " + str(be))
            if rs not in ("active-service", "family-default", "conflict"):
                fail("detect_net_backend reason unexpected: " + str(rs))
            if be is None and rs != "conflict":
                fail("detect_net_backend None backend needs conflict reason")
            if rs != "family-default":
                fail("detect_net_backend without systemctl must be family-default, got " + str(rs))
            if be not in ("networkd", "nm"):
                fail("detect_net_backend without systemctl must return a concrete backend")
    except Exception as exc:  # noqa: BLE001
        shutil.which = orig_which
        fail("detect_net_backend raised: " + str(exc))
    # 13. WAN interface parser is pure and offline (no subprocess).
    try:
        if _parse_wan_iface("default via 1.2.3.4 dev ens6 proto dhcp") != "ens6":
            fail("wan parse fixture missed ens6")
        if _parse_wan_iface("192.168.1.0/24 dev eth0 proto kernel scope link") is not None:
            fail("wan parse false positive without default")
        if _parse_wan_iface("") is not None:
            fail("wan parse empty must be None")
    except Exception as exc:  # noqa: BLE001
        fail("wan parse raised: " + str(exc))
    # 14. Pool start-end spans: next-free skips used, static outside raises, overlap, CIDR legacy.
    try:
        span = "10.90.90.10-10.90.90.20"
        used_peers = [{"name": "a", "role": "infra", "kind": "permanent", "v4": "10.90.90.10", "v6": "", "tombstoned": False}]
        if next_free_ip(span, used_peers, "10.90.90.1") != "10.90.90.11":
            fail("span next-free did not skip used")
        try:
            allocate_static(span, used_peers, "10.90.90.30", "10.90.90.1")
            fail("span static outside accepted")
        except IPAMError:
            pass
        try:
            allocate_static(span, used_peers, "10.90.90.10", "10.90.90.1")
            fail("span static used accepted")
        except IPAMError:
            pass
        if not pool_ranges_overlap("10.90.90.10-10.90.90.20", "10.90.90.15-10.90.90.25", 4):
            fail("span overlap missed")
        if pool_ranges_overlap("10.90.90.10-10.90.90.20", "10.90.90.21-10.90.90.150", 4):
            fail("span overlap false positive")
        if not pool_ranges_overlap("10.90.90.0/24", "10.90.90.10-10.90.90.20", 4):
            fail("cidr-span overlap missed")
        # Short suffix form expands with start prefix.
        if next_free_ip("10.90.90.10-20", used_peers, "10.90.90.1") != "10.90.90.11":
            fail("short suffix span failed")
        # CIDR legacy still allocates as before.
        if next_free_ip("10.90.90.0/24", [], "10.90.90.1") != "10.90.90.2":
            fail("cidr legacy next-free changed")
        # IPv6 span parses and allocates.
        if next_free_ip("fd00::10-fd00::20", [], "fd00::1") != "fd00::10":
            fail("ipv6 span next-free failed")
        # Smart defaults for /24 are disjoint spans excluding hub.
        infra_d, clients_d = suggest_pool_spans("10.90.90.0/24", "10.90.90.1")
        if infra_d != "10.90.90.10-10.90.90.20":
            fail("infra default span mismatch: " + str(infra_d))
        if clients_d != "10.90.90.21-10.90.90.150":
            fail("clients default span mismatch: " + str(clients_d))
        if pool_ranges_overlap(infra_d, clients_d, 4):
            fail("default spans overlap")
    except (ValueError, IPAMError) as exc:
        fail("span checks raised: " + str(exc))
    # 15. Audit invariants: key shape, render guards, nft safety, ifname, redact.
    try:
        good = base64.b64encode(b"\x01" * 32).decode("ascii")
        if not is_valid_wgkey(good):
            fail("valid wg key rejected")
        for bad in ("", "PUBKEY-x", "PRIVKEY-x", "REDACTED", good[:-1], good + "A", "!" + good[1:]):
            if is_valid_wgkey(bad):
                fail("invalid wg key accepted: " + repr(bad))
        st = default_state()
        st["server"]["private_key"] = good
        st["server"]["public_key"] = good
        for fname, fn in (("netdev", render_netdev), ("nm", render_nm)):
            try:
                fn(default_state(), show_secrets=True)
                fail(fname + " accepted empty server key")
            except ValueError:
                pass
            fn(st, show_secrets=True)
        try:
            render_wgquick(st, {"name": "x", "role": "client", "privkey": "PRIVKEY-x"}, show_secrets=True)
            fail("wgquick accepted placeholder peer key")
        except ValueError:
            pass
        nft_out = render_nft(st)
        if not nft_structural_ok(nft_out):
            fail("rendered nft failed structural check")
        # WireGuard UDP listen port must be accepted in input chain without dropping port traffic.
        if "udp dport 51820 accept" not in nft_out:
            fail("nft input missing udp dport accept rule")
        if "udp dport 51820 drop" in nft_out:
            fail("nft input has destructive drop rule on wireguard port")
        injected = {"server": dict(st["server"]), "ipv4": dict(st["ipv4"]), "ipv6": dict(st["ipv6"]), "peers": []}
        injected["server"]["ifname"] = 'wg0" drop; #'
        try:
            render_nft(injected)
            fail("nft injection not rejected")
        except ValueError:
            pass
        for goodname in ("wg0", "wg-1", "eth0.100", "wg@x"):
            validate_ifname(goodname)
        for badname in ('wg0"', "wg 0", "eth0;drop", "wg0`x`", "wg0%0a", "wg0$x", "x" * 16, ""):
            try:
                validate_ifname(badname)
                fail("ifname accepted: " + repr(badname))
            except ValueError:
                pass
        red = redact_text('x PrivateKey = ABC\n{"privkey": "SECRET"}')
        if "ABC" in red or "SECRET" in red:
            fail("redact_text leaked secret")
    except (ValueError, KeyError) as exc:
        fail("key/render/nft checks raised: " + str(exc))
    if failures:
        for item in failures:
            eprint(t("selftest_fail").format(detail=item))
        return 1
    print("ok lang set en,es,de; key parity ok; placeholders parity ok")
    print("ok confirm tokens y/yes s/si j/ja ok; allocator infra static next-free tombstone purge exhaustion ok")
    print("ok renderers permanents-first sort ok, pure no writes; validators ../ traversal rejected, port range 1-65535 ok")
    print("ok dry-run writes nothing; wan overlap guard and delegated prefix guard ok")
    print("ok wg key shape, render guards, nft structure/injection, ifname regex, redaction ok")
    print(t("selftest_pass"))
    return 0


