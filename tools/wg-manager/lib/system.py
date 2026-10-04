# system.py
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from .constants import SYSROOT
from .crypto import validate_key_material
from .errors import WgError
from .i18n import t
from .presentation import emit, eprint, note, section
from .renderers import (
    _systemd_version,
    firewalld_argv,
    render_expire_service,
    render_expire_timer,
    render_netdev,
    render_network,
    render_nft,
    render_nm,
    render_sysctl,
    render_wg_syncconf,
)
from .state import _mkdir_private, atomic_write, state_dir
from .validators import validate_ifname, validate_nft_content


def _sp(path):
    """Audit fix: C5 - prefix system paths with the SYSROOT test seam."""
    return str(SYSROOT) + str(path)


def _manager_exe():
    """Absolute manager binary for timer units (never a bare PATH lookup).

    Prefer the entrypoint actually running (the installed zipapp invoked as
    `wg-manager`), then a PATH lookup, then a deterministic fallback. A bare
    name would be resolved through the caller's PATH at sweep time, which is a
    privilege-escalation vector for a root oneshot.
    """
    argv0 = sys.argv[0] if getattr(sys, "argv", None) else ""
    if argv0:
        candidate = Path(argv0)
        if candidate.name == "wg-manager" and candidate.is_absolute():
            try:
                if candidate.exists() and not candidate.is_symlink():
                    return str(candidate.resolve())
            except OSError:
                pass
    exe = shutil.which("wg-manager")
    if exe:
        return exe
    return "/usr/local/bin/wg-manager"


def _timer_unit_paths():
    """(service, timer) system paths for the expiry sweep."""
    return (
        _sp("/etc/systemd/system/wg-manager-expire.service"),
        _sp("/etc/systemd/system/wg-manager-expire.timer"),
    )


def _needs_expiry_timer(state):
    """True when any non-tombstoned peer carries an expiry date."""
    try:
        peers = state.get("peers", []) if isinstance(state, dict) else []
    except AttributeError:
        return False
    for peer in peers:
        if isinstance(peer, dict) and not peer.get("tombstoned") and peer.get("expires_at") is not None:
            return True
    return False


def _remove_tracked(path, written):
    """Backup (if any) then remove a file, recording the pair for rollback."""
    backup = backup_system_file(str(path))
    p = Path(path)
    try:
        if p.exists() or p.is_symlink():
            os.unlink(str(p))
    except OSError as exc:
        eprint(str(exc))
        raise
    written.append((str(path), str(backup) if backup else None))


def _revert_timer_live():
    """Best-effort disable of a freshly created expiry timer after a failed apply."""
    ctl = shutil.which("systemctl")
    if ctl and _systemd_is_init():
        _run_best_effort([ctl, "disable", "--now", "wg-manager-expire.timer"])
        _run_best_effort([ctl, "daemon-reload"])


def require_apply(args, cmd):
    """Enforce dry-run default; privileged writes need --apply --yes --sudo.

    `--dry-run` always wins, even when combined with `--apply`, so a preview
    can never escalate into a write by accident.
    """
    if getattr(args, "dry_run", False):
        emit(note(t("msg_dry_run"), "dryrun", args, indent=1))
        return False
    if not getattr(args, "apply", False):
        emit(note(t("msg_dry_run"), "dryrun", args, indent=1))
        return False
    if not getattr(args, "yes", False):
        raise WgError(note(t("err_need_apply_yes"), "err", args, indent=1), 2)
    if SYSROOT:
        # Test seam: every system path is already redirected under SYSROOT
        # (and firewall execution is skipped), so a sandboxed apply does not
        # need root. Production never defines this variable. The environment
        # check keeps the seam out of reach of a stray env var in production.
        if os.environ.get("WG_MANAGER_ALLOW_SYSROOT_APPLY") == "1":
            return True
        raise WgError(note(t("err_need_root").format(cmd=cmd), "err", args, indent=1))
    try:
        euid = os.geteuid()
    except AttributeError:
        euid = 1000
    if euid != 0 and not getattr(args, "sudo", False):
        raise WgError(note(t("err_need_root").format(cmd=cmd), "err", args, indent=1))
    if euid != 0 and getattr(args, "sudo", False):
        sudo = shutil.which("sudo")
        if not sudo:
            raise WgError(note(t("err_need_root").format(cmd=cmd), "err", args, indent=1))
        # Re-exec the real entrypoint (repo main.py or the installed zipapp),
        # never this library module.
        entry = os.path.abspath(sys.argv[0] or "")
        if not entry or not os.path.exists(entry):
            raise WgError(note(t("err_need_root").format(cmd=cmd), "err", args, indent=1))
        os.execvp(sudo, [sudo, sys.executable, entry] + sys.argv[1:])
    return True



def _read_os_release():
    """Parse /etc/os-release into dict, empty on failure."""
    info = {}
    try:
        text = Path("/etc/os-release").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return info
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line or line.startswith("#"):
            continue
        key, _, val = line.partition("=")
        info[key.strip()] = val.strip().strip('"').strip("'")
    return info


def _is_rhel_like(info=None):
    """True for RHEL/Fedora family based on ID/ID_LIKE."""
    if info is None:
        info = _read_os_release()
    blob = (str(info.get("ID", "")) + " " + str(info.get("ID_LIKE", ""))).lower()
    for token in ("rhel", "fedora", "centos", "rocky", "alma", "ol", "redhat"):
        if token in blob:
            return True
    return False


def detect_firewall_default():
    """Firewall default: dnf/RHEL family -> firewalld, else nft."""
    try:
        info = _read_os_release()
        if _is_rhel_like(info):
            return "firewalld"
        if shutil.which("dnf"):
            return "firewalld"
    except (OSError, ValueError):
        pass
    return "nft"


def _is_service_active(ctl, svc):
    """Best-effort systemctl is-active check; never raises."""
    try:
        proc = subprocess.run([ctl, "is-active", svc], capture_output=True, text=True, timeout=5, check=False)
        return str(proc.stdout or "").strip() == "active"
    except (OSError, subprocess.SubprocessError):
        return False


def _systemd_is_init():
    """True when systemd is the running init (skips containers/chroots without it)."""
    try:
        return Path(_sp("/run/systemd/system")).is_dir()
    except OSError:
        return False


def _backend_service(backend):
    """systemd unit name for the selected network backend."""
    return "NetworkManager" if backend == "nm" else "systemd-networkd"


def _precheck_backend(backend):
    """Refuse writes when the selected backend service is not running.

    Without this, applying networkd files on a host where systemd-networkd is
    inactive writes files, fails post-verify and rolls everything back, which
    looks like a mysterious 'interface missing' failure.
    """
    if SYSROOT or not _systemd_is_init():
        return
    ctl = shutil.which("systemctl")
    if not ctl:
        return
    svc = _backend_service(backend)
    if not _is_service_active(ctl, svc):
        raise ValueError(t("err_backend_inactive").format(backend=backend, svc=svc))


def _precheck_firewall(firewall):
    """Fail fast when the selected firewall engine cannot be applied."""
    if firewall == "firewalld":
        if not SYSROOT and not shutil.which("firewall-cmd"):
            raise ValueError(t("err_firewall_unavailable").format(engine="firewalld", binary="firewall-cmd"))
    elif not SYSROOT and not shutil.which("nft"):
        raise ValueError(t("err_firewall_unavailable").format(engine="nft", binary="nft"))


_SYSCTL_ORIGINAL_KEYS = (
    "net.ipv4.ip_forward",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
    "net.ipv6.conf.all.forwarding",
)


def snapshot_sysctl_original(state):
    """Record live sysctl values once, so uninstall can restore the host.

    Reads the real /proc/sys (read-only); the SYSROOT seam only affects where
    files are written, and uninstall never writes sysctl under SYSROOT.
    """
    srv = state.setdefault("server", {})
    if not isinstance(srv, dict) or srv.get("sysctl_original"):
        return
    keys = list(_SYSCTL_ORIGINAL_KEYS)
    try:
        from .renderers import render_sysctl as _render_sysctl
        for line in _render_sysctl(state).splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key = line.split("=", 1)[0].strip()
            if key.startswith("net.") and key not in keys:
                keys.append(key)
    except (OSError, ValueError):
        pass
    original = {}
    for key in keys:
        path = Path("/proc/sys/" + key.replace(".", "/"))
        try:
            if path.exists():
                original[key] = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
    if original:
        srv["sysctl_original"] = original


def _systemd_network_gid():
    """Find GID for systemd-networkd (group systemd-network or user's gid)."""
    try:
        import grp
        return grp.getgrnam("systemd-network").gr_gid
    except (KeyError, OSError, ImportError):
        pass
    try:
        import pwd
        return pwd.getpwnam("systemd-network").pw_gid
    except (KeyError, OSError, ImportError):
        pass
    ctl = shutil.which("systemctl")
    if ctl:
        rc, out, _ = _run_capture([ctl, "show", "-p", "Group", "systemd-networkd"])
        if rc == 0 and "=" in out:
            grp_name = out.split("=", 1)[1].strip()
            if grp_name:
                try:
                    import grp
                    return grp.getgrnam(grp_name).gr_gid
                except (KeyError, OSError, ImportError):
                    pass
        rc, out, _ = _run_capture([ctl, "show", "-p", "User", "systemd-networkd"])
        if rc == 0 and "=" in out:
            user_name = out.split("=", 1)[1].strip()
            if user_name:
                try:
                    import pwd
                    return pwd.getpwnam(user_name).pw_gid
                except (KeyError, OSError, ImportError):
                    pass
    return None


def _net_diagnostics(ifname, backend, args=None):
    """Read-only, best-effort diagnostics for a failed apply; never raises."""
    lines = ["", section("diagnostics", args)]
    svc = _backend_service(backend)
    ctl = shutil.which("systemctl")
    if ctl and _systemd_is_init():
        _rc, out, _err = _run_capture([ctl, "is-active", svc])
        lines.append(note(svc + ": " + (out.strip() or "unknown"), "info", args, indent=1))
        _rc, out, _err = _run_capture([ctl, "status", svc, "--no-pager", "-n", "0"])
        for ln in [l for l in out.strip().splitlines() if l.strip()][:6]:
            lines.append("    " + ln)
    nctl = shutil.which("networkctl")
    if nctl:
        _rc, out, _err = _run_capture([nctl, "status", ifname])
        for ln in [l for l in out.strip().splitlines() if l.strip()][:6]:
            lines.append("    " + ln)
    jctl = shutil.which("journalctl")
    if jctl and _systemd_is_init():
        _rc, out, _err = _run_capture([jctl, "-u", svc, "-n", "50", "--no-pager"])
        for ln in [l for l in out.strip().splitlines() if l.strip()][-25:]:
            lines.append("    " + ln)
    if backend == "nm":
        cfg = _sp("/etc/NetworkManager/system-connections/wg-manager.nmconnection")
    else:
        cfg = _sp("/etc/systemd/network/90-" + ifname + ".netdev")
    try:
        present = Path(cfg).exists()
    except OSError:
        present = False
    lines.append(note("config file written: " + ("yes" if present else "no"), "info", args, indent=1))
    return lines


def _family_default_backend():
    """Family default without writes: RHEL-like -> nm, else networkd."""
    try:
        if _is_rhel_like():
            return "nm"
    except (OSError, ValueError):
        pass
    return "networkd"


def detect_net_backend():
    """Best-effort network backend detection; never raises, never writes.

    Returns (backend|None, reason) where backend is networkd|nm|None and
    reason is one of active-service|family-default|conflict.
    """
    try:
        ctl = None
        try:
            ctl = shutil.which("systemctl")
        except (OSError, ValueError):
            ctl = None
        if ctl:
            netd = _is_service_active(ctl, "systemd-networkd")
            nm = _is_service_active(ctl, "NetworkManager")
            if netd and not nm:
                return ("networkd", "active-service")
            if nm and not netd:
                return ("nm", "active-service")
            if netd and nm:
                return (None, "conflict")
        return (_family_default_backend(), "family-default")
    except Exception:  # noqa: BLE001
        return ("networkd", "family-default")


def _rotate_system_backups(bdir, keep=20):
    """Rotate sys-* backups as pairs (file + .mode sidecar), keeping `keep` files."""
    try:
        files = [p for p in sorted(Path(bdir).glob("sys-*")) if not p.name.endswith(".mode")]
    except OSError:
        return
    for old in files[:-keep]:
        try:
            old.unlink()
        except OSError:
            pass
        sidecar = Path(str(old) + ".mode")
        try:
            if sidecar.exists():
                sidecar.unlink()
        except OSError:
            pass


def backup_system_file(path):
    """Backup an existing file to backups/sys-<ts>-<pid>-<basename> (rotate 20).

    A `<backup>.mode` sidecar remembers the original permissions so rollback
    restores 0644 configs as 0644 while the backup itself stays 0600 (it may
    contain private keys).
    """
    p = Path(path)
    try:
        if not p.exists() or not p.is_file():
            return None
        bdir = state_dir() / "backups"
        _mkdir_private(bdir)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        dest = bdir / ("sys-" + stamp + "-" + str(os.getpid()) + "-" + p.name)
        try:
            original_mode = p.stat().st_mode & 0o7777
        except OSError:
            original_mode = None
        shutil.copy2(str(p), str(dest))
        try:
            os.chmod(dest, 0o600)
        except OSError:
            pass
        if original_mode is not None:
            try:
                sidecar = Path(str(dest) + ".mode")
                sidecar.write_text(oct(original_mode) + "\n", encoding="ascii")
                os.chmod(sidecar, 0o600)
            except OSError:
                pass
        print(t("sys_backup").format(path=str(p), backup=str(dest)))
        _rotate_system_backups(bdir, 20)
        return dest
    except OSError:
        return None


def _run_best_effort(argv):
    """Run a system command best-effort, never raise."""
    try:
        subprocess.run(argv, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        pass
    return True


def _restorecon(path):
    """Restore SELinux security context on path if restorecon is available."""
    r_exe = shutil.which("restorecon")
    if r_exe:
        _run_best_effort([r_exe, "-F", str(path)])


def write_system_file(path, content, mode):
    """Backup then atomically write a real system file."""
    existed = Path(path).exists()
    backup = backup_system_file(path)
    if existed and backup is None:
        raise OSError("backup failed for " + str(path) + "; refusing to overwrite")
    atomic_write(Path(path), content, mode=mode)
    _restorecon(path)
    emit(note(t("sys_wrote").format(path=str(path)), "applied", indent=1))


def _write_tracked(path, content, mode, written, gid=None):
    """Audit fix: C5 - backup + atomic write, recording the pair for rollback."""
    existed = Path(path).exists()
    backup = backup_system_file(path)
    if existed and backup is None:
        # Fail closed: overwriting without a restorable backup must not proceed.
        raise OSError("backup failed for " + str(path) + "; refusing to overwrite")
    atomic_write(Path(path), content, mode=mode, gid=gid)
    _restorecon(path)
    emit(note(t("sys_wrote").format(path=str(path)), "applied", indent=1))
    written.append((str(path), str(backup) if backup else None))


def _run_capture(argv, timeout=15):
    """Audit fix: C5 - run a command and return (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except (OSError, subprocess.SubprocessError):
        return None, "", ""


def _ensure_nft_include(main_conf, nft_file, written=None):
    """Ensure include line for nft_file exists in main_conf (tracked for rollback)."""
    line = 'include "' + str(nft_file) + '"'
    alt = 'include "/etc/nftables.d/*.nft"'
    p = Path(main_conf)
    try:
        if p.exists():
            try:
                current = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                current = ""
            for candidate in current.splitlines():
                if candidate.strip() in (line, alt):
                    return True
            backup = backup_system_file(str(p))
            if backup is None:
                return False
            new_content = current
            if new_content and not new_content.endswith("\n"):
                new_content += "\n"
            new_content += line + "\n"
            try:
                original_mode = p.stat().st_mode & 0o7777
            except OSError:
                original_mode = 0o644
            atomic_write(p, new_content, mode=original_mode)
            emit(note(t("sys_wrote").format(path=str(p)), "applied", indent=1))
            if written is not None:
                written.append((str(p), str(backup) if backup else None))
            return True
        # Create minimal conf when parent exists.
        if p.parent.exists():
            backup = backup_system_file(str(p))
            atomic_write(p, "# Managed by wg-manager.\n" + line + "\n", mode=0o644)
            emit(note(t("sys_wrote").format(path=str(p)), "applied", indent=1))
            if written is not None:
                written.append((str(p), str(backup) if backup else None))
            return True
    except OSError as exc:
        eprint(str(exc))
    return False


def _clean_host_filter_rules(nft_exe=None):
    """Surgically remove existing wg-manager tagged rules from table inet filter by handle."""
    if SYSROOT:
        return []
    exe = nft_exe or shutil.which("nft")
    if not exe:
        return []
    rc, out, _err = _run_capture([exe, "-a", "list", "table", "inet", "filter"])
    if rc != 0 or not out:
        return []
    current_chain = None
    to_delete = []
    for line in out.splitlines():
        chain_m = re.match(r"^\s*chain\s+([A-Za-z0-9_.\-]+)\s*\{", line)
        if chain_m:
            current_chain = chain_m.group(1)
            continue
        if current_chain and 'comment "wg-manager"' in line:
            handle_m = re.search(r"handle\s+(\d+)\s*$", line.strip())
            if handle_m:
                try:
                    to_delete.append((current_chain, int(handle_m.group(1))))
                except ValueError:
                    continue
    deleted = []
    for chain, handle in sorted(to_delete, key=lambda item: item[1], reverse=True):
        drc, _out, _err = _run_capture([exe, "delete", "rule", "inet", "filter", chain, "handle", str(handle)])
        if drc == 0:
            deleted.append((chain, str(handle)))
    return deleted


def _link_kind(ifname):
    """Best-effort link kind via `ip -d link show`; None when unknown."""
    ip_exe = shutil.which("ip")
    if not ip_exe:
        return None
    rc, out, _err = _run_capture([ip_exe, "-d", "link", "show", ifname])
    if rc != 0 or not out:
        return None
    low = out.lower()
    if "wireguard" in low:
        return "wireguard"
    if "loopback" in low or " link/loopback " in low:
        return "loopback"
    return "other"


def _is_owned_link(ifname, state):
    """True only for a WireGuard link carrying our managed marker."""
    try:
        srv = (state.get("server", {}) or {}) if isinstance(state, dict) else {}
        if str(srv.get("ifname", "") or "") != str(ifname):
            return False
    except (AttributeError, TypeError, ValueError):
        return False
    kind = _link_kind(ifname)
    if kind is None:
        # Offline / sysfs fallback: marker file implies ownership.
        try:
            marker = Path(_sp("/etc/systemd/network/90-" + str(ifname) + ".netdev"))
            nm_marker = Path(_sp("/etc/NetworkManager/system-connections/wg-manager.nmconnection"))
            if marker.exists() or nm_marker.exists():
                return True
        except OSError:
            pass
        return False
    return kind == "wireguard"


def _verify_iface(ifname, tries=1, delay=0.0):
    """Audit fix: C5 - does the interface exist via ip or sysfs (with polling)."""
    ip_exe = shutil.which("ip")
    for attempt in range(max(1, tries)):
        if ip_exe:
            rc, _out, _err = _run_capture([ip_exe, "link", "show", ifname])
            if rc == 0:
                return True
        elif Path(_sp("/sys/class/net/" + ifname)).exists():
            return True
        if attempt + 1 < max(1, tries):
            time.sleep(delay)
    return False


def _sysctl_exe():
    """sysctl binary usable in this environment (never the host one under SYSROOT)."""
    exe = shutil.which("sysctl")
    if not exe:
        return None
    if SYSROOT and not Path(_sp("/proc/sys")).exists():
        return None
    return exe


def _post_verify(state, ifname, backend="networkd", firewall="nftables", tries=1, delay=0.0):
    """Audit fix: C5 - return a failure reason or None when the apply is healthy."""
    if SYSROOT:
        # Sandboxed/test apply: the live kernel is out of scope, so verify the
        # staged configuration files instead of an interface that cannot exist.
        if backend == "nm":
            expected = _sp("/etc/NetworkManager/system-connections/wg-manager.nmconnection")
        else:
            expected = _sp("/etc/systemd/network/90-" + ifname + ".netdev")
        if not Path(expected).exists():
            return "staged config " + expected + " missing"
        return None
    if not _verify_iface(ifname, tries=tries, delay=delay):
        return "interface " + ifname + " missing"
    wg = shutil.which("wg")
    if wg:
        rc, _out, _err = _run_capture([wg, "show", ifname, "dump"])
        if rc != 0:
            return "wg show " + ifname + " failed"
    fwd_path = Path(_sp("/proc/sys/net/ipv4/ip_forward"))
    try:
        if fwd_path.exists() and fwd_path.read_text(encoding="utf-8").strip() != "1":
            return "ip_forward disabled"
    except OSError:
        pass
    if not SYSROOT and firewall != "firewalld":
        exe = shutil.which("nft")
        if exe:
            rc, _out, _err = _run_capture([exe, "list", "table", "inet", "wg_manager"])
            if rc != 0:
                return "nft table inet wg_manager missing or inactive"
    if not SYSROOT and firewall == "firewalld":
        fw = shutil.which("firewall-cmd")
        if fw:
            rc, out, _err = _run_capture([fw, "--state"])
            if rc == 0 and "running" in (out or ""):
                qrc, _o, _e = _run_capture([fw, "--zone=trusted", "--query-interface=" + str(ifname)])
                if qrc != 0:
                    return "firewalld trusted zone missing interface " + str(ifname)
    return None


def _sync_wg_peers(state, ifname):
    """Apply peer changes to a running interface via `wg syncconf`.

    `networkctl reload` and NM profile reloads do not update WireGuard peers on
    an already-running link. Returns True when the in-kernel sync succeeded.
    The private-key temp lives 0600 inside the state dir, never in /tmp.
    """
    wg = shutil.which("wg")
    if not wg or not _verify_iface(ifname):
        return False
    sync_content = render_wg_syncconf(state, show_secrets=True)
    _mkdir_private(state_dir())
    fd, tmp_path = tempfile.mkstemp(prefix=".syncconf-", suffix=".conf", dir=str(state_dir()))
    try:
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as tf:
            tf.write(sync_content)
        rc, _out, _err = _run_capture([wg, "syncconf", ifname, tmp_path])
        return rc == 0
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _wan_global_addrs(wan):
    """Snapshot global-scope addresses on an interface; None when unknown.

    Best-effort only: a missing `ip`, a failed call or unparsable output
    disables the post-apply WAN guard instead of failing the apply.
    """
    ip_exe = shutil.which("ip")
    if not ip_exe or not wan:
        return None
    rc, out, _err = _run_capture([ip_exe, "-o", "addr", "show", "dev", str(wan)])
    if rc != 0:
        return None
    found = set()
    for line in str(out or "").splitlines():
        # iproute2 -o shape: idx: ifname family addr/plen ... scope <scope>
        parts = line.split()
        if len(parts) < 4 or parts[1] != str(wan):
            continue
        family, addr = parts[2], parts[3].split("/")[0]
        if family not in ("inet", "inet6"):
            continue
        if "." not in addr and ":" not in addr:
            continue
        try:
            scope = parts[parts.index("scope") + 1]
        except (ValueError, IndexError):
            continue
        if scope == "global":
            found.add(family + " " + addr)
    return found


def _warn_if_wan_addrs_lost(wan, before):
    """Loud (non-fatal) warning when the WAN lost addresses across a restart.

    A `systemd-networkd` restart re-manages every interface, so addresses
    added by hand (`ip addr add`, one-shot cloud scripts) vanish unless they
    live in netplan/networkd/ifupdown config. Only a strict shrink warns, so
    a DHCP renumber (same count, new address) stays quiet. Never fails the
    apply: the WireGuard side is fine, the host addressing needs attention.
    """
    if not before:
        return
    after = _wan_global_addrs(wan)
    if after is None:
        return
    lost = sorted(before - after)
    if lost and len(after) < len(before):
        eprint(note(t("warn_wan_addr_lost").format(wan=wan, addrs=", ".join(lost)), "warn"))


def get_wg_live_dump(ifname):
    """Query wg show <ifname> dump. Return dict: pubkey -> {endpoint, allowed_ips, handshake, rx, tx}."""
    exe = shutil.which("wg")
    if not exe:
        return {}
    try:
        proc = subprocess.run([exe, "show", ifname, "dump"], capture_output=True, text=True, timeout=5, check=False)
        if proc.returncode != 0:
            return {}
        res = {}
        for line in proc.stdout.splitlines()[1:]:
            f = line.split("\t")
            if len(f) >= 7:
                try:
                    res[f[0]] = {
                        "endpoint": f[2] if f[2] != "(none)" else "-",
                        "allowed_ips": f[3],
                        "handshake": int(f[4]),
                        "rx": int(f[5]),
                        "tx": int(f[6]),
                    }
                except (ValueError, IndexError):
                    pass
        return res
    except (OSError, subprocess.SubprocessError):
        return {}


def format_bytes(n):
    if not isinstance(n, (int, float)) or n <= 0:
        return "0 B"
    if n < 1024:
        return str(int(n)) + " B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.1f} GB"


def format_handshake_age(epoch_secs, now_secs):
    if not epoch_secs:
        return "never"
    diff = max(0, now_secs - epoch_secs)
    if diff < 60:
        return f"{diff}s ago"
    if diff < 3600:
        return f"{diff // 60}m ago"
    if diff < 86400:
        return f"{diff // 3600}h ago"
    return f"{diff // 86400}d ago"



def _restore_backup_mode(path, backup):
    """Re-apply the original mode recorded by backup_system_file."""
    sidecar = Path(str(backup) + ".mode")
    try:
        if sidecar.exists():
            os.chmod(str(path), int(sidecar.read_text(encoding="ascii").strip(), 8))
    except (OSError, ValueError):
        pass


def _rollback_paths(entries):
    """Audit fix: C5 - restore backups in reverse order, or remove new files."""
    for path, backup in reversed(entries):
        try:
            if backup is not None and Path(backup).exists():
                shutil.copy2(str(backup), str(path))
                _restore_backup_mode(path, backup)
            elif Path(path).exists():
                os.unlink(str(path))
        except OSError as exc:
            eprint(str(exc))


def apply_system_reload(state, backend, firewall, args=None):
    """Audit fix: C5 - precheck, write, verify and rollback system resources."""
    # 0. Persisted choices win over detection, so `reload --backend/--firewall`
    #    stays effective for every later command.
    srv = state.get("server", {}) if isinstance(state, dict) else {}
    backend = str(srv.get("backend") or "") or backend
    firewall = str(srv.get("firewall") or "") or firewall
    # 1. Hard prechecks: invalid key material, names or a missing firewall
    #    engine abort before any write.
    validate_key_material(state)
    _precheck_backend(backend)
    _precheck_firewall(firewall)
    srv = state.get("server", {})
    ifname = str(srv.get("ifname", "wg0") or "wg0")
    validate_ifname(ifname)
    wan = srv.get("wan_iface") or srv.get("wan") or "eth0"
    validate_ifname(wan)
    if ifname == wan:
        raise ValueError(t("err_invalid_ifname").format(value="ifname == wan_iface (" + ifname + ")"))
    # Snapshot WAN addresses before any restart: a networkd restart flushes
    # hand-added (non-persistent) addresses on every interface, not just wg.
    wan_addrs_before = _wan_global_addrs(wan)
    # 2. Render everything first; a render error aborts before writing.
    nft_content = ""
    nft_file = _sp("/etc/nftables.d/90-wg-manager.nft")
    if firewall != "firewalld":
        nft_content = render_nft(state)
        if not validate_nft_content(nft_content):
            raise ValueError(t("err_nft_invalid"))
    net_gid = _systemd_network_gid() if backend != "nm" else None
    netdev_mode = 0o640 if (backend != "nm" and net_gid is not None) else 0o600
    if backend == "nm":
        backend_files = [(_sp("/etc/NetworkManager/system-connections/wg-manager.nmconnection"), render_nm(state, show_secrets=True), 0o600, None)]
    else:
        ver = _systemd_version()
        if ver is not None and ver >= 256:
            netd_conf = (
                "# Managed by wg-manager. Do not edit manually.\n"
                "[Network]\n"
                "IPv4Forwarding=yes\n"
            )
            if state.get("ipv6", {}).get("mode", "disabled") != "disabled":
                netd_conf += "IPv6Forwarding=yes\n"
        elif ver is not None and ver < 256:
            netd_conf = (
                "# Managed by wg-manager. Do not edit manually.\n"
                "[Network]\n"
                "IPForward=yes\n"
            )
        else:
            netd_conf = (
                "# Managed by wg-manager. Do not edit manually.\n"
                "[Network]\n"
                "IPForward=yes\n"
                "IPv4Forwarding=yes\n"
            )
            if state.get("ipv6", {}).get("mode", "disabled") != "disabled":
                netd_conf += "IPv6Forwarding=yes\n"
        backend_files = [
            (_sp("/etc/systemd/network/90-" + ifname + ".netdev"), render_netdev(state, show_secrets=True), netdev_mode, net_gid),
            (_sp("/etc/systemd/network/90-" + ifname + ".network"), render_network(state), 0o644, None),
            (_sp("/etc/systemd/networkd.conf.d/80-wg-manager.conf"), netd_conf, 0o644, None),
        ]
    sysctl_content = render_sysctl(state)
    snapshot_sysctl_original(state)
    written = []
    needs_timer = _needs_expiry_timer(state)
    timer_touched = False
    timer_is_new = False
    # 3. Backups + atomic writes (all tracked for rollback).
    try:
        for entry in backend_files:
            _write_tracked(entry[0], entry[1], entry[2], written, gid=entry[3])
        _write_tracked(_sp("/etc/sysctl.d/90-wg-manager.conf"), sysctl_content, 0o644, written)
        if firewall != "firewalld":
            try:
                Path(_sp("/etc/nftables.d")).mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
            _write_tracked(nft_file, nft_content, 0o644, written)
            info = _read_os_release()
            main_conf = _sp("/etc/sysconfig/nftables.conf") if _is_rhel_like(info) else _sp("/etc/nftables.conf")
            if not _ensure_nft_include(main_conf, nft_file, written):
                eprint("nft include could not be persisted; rolling back")
                _rollback_paths(written)
                return False
        # Expiry sweep timer: only when some peer carries an expiry date;
        # otherwise remove our units so hosts without expirations stay clean.
        svc_path, timer_path = _timer_unit_paths()
        if needs_timer:
            timer_is_new = not (Path(svc_path).exists() and Path(timer_path).exists())
            _write_tracked(svc_path, render_expire_service(_manager_exe()), 0o644, written)
            _write_tracked(timer_path, render_expire_timer(), 0o644, written)
            timer_touched = True
        else:
            if Path(svc_path).exists() or Path(svc_path).is_symlink():
                _remove_tracked(svc_path, written)
                timer_touched = True
            if Path(timer_path).exists() or Path(timer_path).is_symlink():
                _remove_tracked(timer_path, written)
                timer_touched = True
    except OSError as exc:
        eprint(str(exc))
        _rollback_paths(written)
        if timer_touched and timer_is_new:
            _revert_timer_live()
        return False
    # 4. Activate network backend: load module, reload first, conditional restart, then verify.
    mod = shutil.which("modprobe")
    if mod:
        _run_best_effort([mod, "wireguard"])
    if backend == "nm":
        nmcli = shutil.which("nmcli")
        if nmcli:
            _run_best_effort([nmcli, "con", "reload"])
            # `device reapply` applies changed profile properties without a full
            # reactivation cycle; fall back to `con up` when unsupported.
            reapply_rc, _o, _e = _run_capture([nmcli, "device", "reapply", ifname])
            if reapply_rc != 0:
                _run_best_effort([nmcli, "con", "up", "wg-manager-" + ifname])
        # Profile reload/reactivation may not push peer changes into the kernel.
        _sync_wg_peers(state, ifname)
    else:
        nctl = shutil.which("networkctl")
        if nctl:
            _run_best_effort([nctl, "reload"])
            _run_best_effort([nctl, "reconfigure", ifname])
        # Live kernel sync: networkctl reload does NOT update .netdev WireGuard peers
        # on running links. If wg is available, sync peers in-place via wg syncconf.
        if not _sync_wg_peers(state, ifname):
            if not _verify_iface(ifname, tries=8, delay=0.25):
                ctl = shutil.which("systemctl")
                if ctl:
                    _run_best_effort([ctl, "restart", "systemd-networkd"])
                # networkd needs a moment to create the netdev after a restart.
                _verify_iface(ifname, tries=20, delay=0.5)
            elif not SYSROOT:
                # Live host without wg syncconf: recreate link so networkd loads peers from netdev
                # Never delete a link we do not own (e.g. a typo pointing at eth0).
                ip_exe = shutil.which("ip")
                ctl = shutil.which("systemctl")
                if ip_exe and ctl and _systemd_is_init():
                    if _is_owned_link(ifname, state):
                        _run_best_effort([ip_exe, "link", "delete", "dev", ifname])
                        _run_best_effort([ctl, "restart", "systemd-networkd"])
                        _verify_iface(ifname, tries=20, delay=0.5)
                    else:
                        eprint("refusing to delete non-wireguard/foreign link " + ifname)
    # 5. sysctl after the interface exists so per-iface keys apply.
    ctl_sys = _sysctl_exe()
    if ctl_sys:
        _run_best_effort([ctl_sys, "--system"])
    # 6. Firewall (validated/rendered earlier).
    ufw_added = []
    if firewall == "firewalld":
        fw = shutil.which("firewall-cmd")
        if fw:
            for argv in firewalld_argv(state):
                rc, _out, err = _run_capture([fw] + list(argv[1:]))
                if rc != 0:
                    eprint((err or "").strip() or ("firewall-cmd failed: " + " ".join(argv[1:])))
                    _rollback_paths(written)
                    if timer_touched and timer_is_new:
                        _revert_timer_live()
                    return False
    else:
        exe = shutil.which("nft")
        if exe:
            _clean_host_filter_rules(exe)
            rc, _out, err = _run_capture([exe, "-f", nft_file])
            if rc not in (0, None):
                # A rejected ruleset is a failed apply: roll back files and the
                # live ruleset instead of reporting success.
                eprint(err.strip() or "nft apply failed")
                _rollback_paths(written)
                if Path(nft_file).exists():
                    _run_best_effort([exe, "-f", nft_file])
                if timer_touched and timer_is_new:
                    _revert_timer_live()
                return False
        # Internal host firewall support: if UFW is active on Debian/Ubuntu, allow WireGuard port and routing.
        ufw = shutil.which("ufw")
        if ufw:
            rc, out, _ = _run_capture([ufw, "status"])
            if rc == 0 and "Status: active" in out:
                port = srv.get("port", 51820)
                rc1, _, _ = _run_capture([ufw, "allow", str(port) + "/udp", "comment", "wg-manager"])
                if rc1 == 0:
                    ufw_added.append("allow")
                rc2, _, _ = _run_capture([ufw, "route", "allow", "in", "on", ifname])
                if rc2 == 0:
                    ufw_added.append("route")
    # 7. Post-verify: rollback on any failure.
    reason = _post_verify(state, ifname, backend=backend, firewall=firewall, tries=20, delay=0.5)
    if reason:
        emit(_net_diagnostics(ifname, backend, args))
        _rollback_paths(written)
        if timer_touched and timer_is_new:
            _revert_timer_live()
        # Revert UFW pinholes added by this apply.
        if ufw_added:
            ufw = shutil.which("ufw")
            if ufw:
                port = srv.get("port", 51820)
                if "route" in ufw_added:
                    _run_best_effort([ufw, "route", "delete", "allow", "in", "on", ifname])
                if "allow" in ufw_added:
                    _run_best_effort([ufw, "delete", "allow", str(port) + "/udp"])
        # Revert the live firewall too: file rollback alone leaves stale rules.
        if firewall == "firewalld":
            fw = shutil.which("firewall-cmd")
            if fw:
                _run_best_effort([fw, "--reload"])
        else:
            exe = shutil.which("nft")
            if exe:
                if Path(nft_file).exists():
                    _run_best_effort([exe, "-f", nft_file])
                else:
                    for tbl in ("inet wg_manager", "ip wg_manager_nat4", "ip6 wg_manager_nat6"):
                        _run_best_effort([exe, "delete", "table"] + tbl.split())
        ctl_sys = _sysctl_exe()
        if ctl_sys:
            _run_best_effort([ctl_sys, "--system"])
        if backend == "nm":
            nmcli = shutil.which("nmcli")
            if nmcli:
                _run_best_effort([nmcli, "con", "reload"])
        else:
            ctl = shutil.which("systemctl")
            if ctl:
                _run_best_effort([ctl, "restart", "systemd-networkd"])
        eprint(note(t("msg_rollback_applied").format(reason=reason), "err", args, indent=1))
        emit(note(t("msg_rollback_restored"), "info", args, indent=1))
        return False
    # 8. Expiry timer live state (only after a verified apply).
    ctl = shutil.which("systemctl")
    if ctl and _systemd_is_init():
        _run_best_effort([ctl, "daemon-reload"])
        if needs_timer:
            _run_best_effort([ctl, "enable", "--now", "wg-manager-expire.timer"])
        else:
            _run_best_effort([ctl, "disable", "--now", "wg-manager-expire.timer"])
    _warn_if_wan_addrs_lost(wan, wan_addrs_before)
    return True


def preview_system_uninstall(state):
    """Return list of resources/paths that would be affected by uninstall."""
    srv = state.get("server", {}) if isinstance(state, dict) else {}
    ifname = str(srv.get("ifname", "wg0") or "wg0")
    return [
        ("WireGuard interface", ifname),
        ("systemd-networkd netdev", _sp("/etc/systemd/network/90-" + ifname + ".netdev")),
        ("systemd-networkd network", _sp("/etc/systemd/network/90-" + ifname + ".network")),
        ("systemd-networkd global config", _sp("/etc/systemd/networkd.conf.d/80-wg-manager.conf")),
        ("NetworkManager connection", _sp("/etc/NetworkManager/system-connections/wg-manager.nmconnection")),
        ("sysctl configuration", _sp("/etc/sysctl.d/90-wg-manager.conf")),
        ("nftables configuration", _sp("/etc/nftables.d/90-wg-manager.nft")),
        ("expiry sweep service", _sp("/etc/systemd/system/wg-manager-expire.service")),
        ("expiry sweep timer", _sp("/etc/systemd/system/wg-manager-expire.timer")),
        ("host base filter rules", "comment 'wg-manager' in inet filter"),
        ("nftables live tables", "inet wg_manager, ip wg_manager_nat4, ip6 wg_manager_nat6"),
        ("firewalld rules", "trusted zone interface " + ifname + ", UDP port " + str(srv.get("port", 51820))),
        ("ufw rules", "allow UDP port " + str(srv.get("port", 51820)) + ", route allow on " + ifname),
        ("state directory", str(state_dir())),
    ]


def apply_system_uninstall(state, args=None):
    """Remove system configurations, live wireguard interface, sysctl, and firewall rules."""
    srv = state.get("server", {}) if isinstance(state, dict) else {}
    ifname = str(srv.get("ifname", "wg0") or "wg0")
    wan = str(srv.get("wan_iface") or srv.get("wan") or "eth0")
    wan_addrs_before = _wan_global_addrs(wan)

    removed = []

    # 1. Bring down and delete WireGuard interface (only if we own it).
    ip_exe = shutil.which("ip")
    if ip_exe:
        if _is_owned_link(ifname, state):
            _run_best_effort([ip_exe, "link", "set", "dev", ifname, "down"])
            _run_best_effort([ip_exe, "link", "delete", "dev", ifname])
        else:
            eprint("refusing to delete non-wireguard/foreign link " + ifname)

    # 2. NetworkManager cleanup (only our wg-manager-<ifname> profile).
    nm_file = Path(_sp("/etc/NetworkManager/system-connections/wg-manager.nmconnection"))
    nmcli = shutil.which("nmcli")
    if nmcli:
        _run_best_effort([nmcli, "con", "down", "wg-manager-" + ifname])
        _run_best_effort([nmcli, "con", "delete", "wg-manager-" + ifname])
    if nm_file.exists():
        try:
            nm_file.unlink()
            removed.append(str(nm_file))
        except OSError:
            pass
    if nmcli:
        _run_best_effort([nmcli, "con", "reload"])

    # 3. systemd-networkd cleanup
    netdev = Path(_sp("/etc/systemd/network/90-" + ifname + ".netdev"))
    network = Path(_sp("/etc/systemd/network/90-" + ifname + ".network"))
    for p in (netdev, network):
        if p.exists():
            try:
                p.unlink()
                removed.append(str(p))
            except OSError:
                pass
    net_dir = Path(_sp("/etc/systemd/network"))
    if net_dir.is_dir():
        for candidate in sorted(net_dir.glob("90-wg*.net*")):
            if candidate.exists() and candidate not in (netdev, network):
                try:
                    candidate.unlink()
                    removed.append(str(candidate))
                except OSError:
                    pass
    netd_dropin = Path(_sp("/etc/systemd/networkd.conf.d/80-wg-manager.conf"))
    if netd_dropin.exists():
        try:
            netd_dropin.unlink()
            removed.append(str(netd_dropin))
        except OSError:
            pass

    nctl = shutil.which("networkctl")
    if nctl:
        _run_best_effort([nctl, "reload"])
    ctl = shutil.which("systemctl")
    if ctl and _systemd_is_init():
        _run_best_effort([ctl, "restart", "systemd-networkd"])

    # 4. sysctl cleanup: remove our file and restore the values captured at
    #    first apply, so uninstall really leaves the host as it was.
    sysctl_conf = Path(_sp("/etc/sysctl.d/90-wg-manager.conf"))
    if sysctl_conf.exists():
        try:
            sysctl_conf.unlink()
            removed.append(str(sysctl_conf))
        except OSError:
            pass
    ctl_sys = _sysctl_exe()
    if ctl_sys:
        _run_best_effort([ctl_sys, "--system"])
        original = srv.get("sysctl_original") if isinstance(srv, dict) else None
        if isinstance(original, dict):
            for key, value in original.items():
                if re.fullmatch(r"net\.[a-z0-9_.]+", str(key)) and re.fullmatch(r"-?\d+", str(value)):
                    _run_best_effort([ctl_sys, "-w", str(key) + "=" + str(value)])

    # 5. firewall cleanup (nftables and firewalld)
    nft_file = Path(_sp("/etc/nftables.d/90-wg-manager.nft"))
    if nft_file.exists():
        try:
            nft_file.unlink()
            removed.append(str(nft_file))
        except OSError:
            pass
    info = _read_os_release()
    main_conf = Path(_sp("/etc/sysconfig/nftables.conf") if _is_rhel_like(info) else _sp("/etc/nftables.conf"))
    if main_conf.exists():
        try:
            content = main_conf.read_text(encoding="utf-8", errors="replace")
            include_needle = 'include "' + str(_sp("/etc/nftables.d/90-wg-manager.nft")) + '"'
            alt_needle = 'include "/etc/nftables.d/90-wg-manager.nft"'
            if include_needle in content or alt_needle in content:
                new_lines = [
                    line for line in content.splitlines()
                    if include_needle not in line and alt_needle not in line and line.strip() != "# Managed by wg-manager."
                ]
                if not new_lines or (len(new_lines) == 1 and not new_lines[0].strip()):
                    main_conf.unlink()
                    removed.append(str(main_conf))
                else:
                    main_conf.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        except OSError:
            pass
    nft_exe = shutil.which("nft")
    if nft_exe:
        _clean_host_filter_rules(nft_exe)
        for tbl in ("inet wg_manager", "ip wg_manager_nat4", "ip6 wg_manager_nat6"):
            _run_best_effort([nft_exe, "delete", "table"] + tbl.split())

    # 6. expiry sweep timer: disable first, then remove our units.
    ctl = shutil.which("systemctl")
    if ctl and _systemd_is_init():
        _run_best_effort([ctl, "disable", "--now", "wg-manager-expire.timer"])
    for unit in ("wg-manager-expire.service", "wg-manager-expire.timer"):
        unit_file = Path(_sp("/etc/systemd/system/" + unit))
        if unit_file.exists() and not unit_file.is_symlink():
            try:
                unit_file.unlink()
                removed.append(str(unit_file))
            except OSError:
                pass
    if ctl and _systemd_is_init():
        _run_best_effort([ctl, "daemon-reload"])

    fw_cmd = shutil.which("firewall-cmd")
    if fw_cmd:
        port = srv.get("port", 51820)
        v4prefix = str(state.get("ipv4", {}).get("prefix", "") or "")
        v6prefix = str(state.get("ipv6", {}).get("prefix", "") or "")
        v6mode = str(state.get("ipv6", {}).get("mode", "disabled") or "disabled")
        _run_best_effort([fw_cmd, "--permanent", "--zone=trusted", "--remove-interface=" + str(ifname)])
        _run_best_effort([fw_cmd, "--permanent", "--zone=trusted", "--remove-port=" + str(port) + "/udp"])
        if v4prefix:
            _run_best_effort([fw_cmd, "--permanent", "--remove-rich-rule", 'rule family="ipv4" source address="' + v4prefix + '" masquerade'])
        if v6mode == "nat66" and v6prefix:
            _run_best_effort([fw_cmd, "--permanent", "--remove-rich-rule", 'rule family="ipv6" source address="' + v6prefix + '" masquerade'])
        _run_best_effort([fw_cmd, "--permanent", "--direct", "--remove-rule", "ipv4", "filter", "FORWARD", "0", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"])
        _run_best_effort([fw_cmd, "--permanent", "--direct", "--remove-rule", "ipv6", "filter", "FORWARD", "0", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"])
        _run_best_effort([fw_cmd, "--reload"])

    ufw_cmd = shutil.which("ufw")
    if ufw_cmd:
        port = srv.get("port", 51820)
        _run_best_effort([ufw_cmd, "route", "delete", "allow", "in", "on", str(ifname)])
        _run_best_effort([ufw_cmd, "delete", "allow", str(port) + "/udp"])

    _warn_if_wan_addrs_lost(wan, wan_addrs_before)
    return removed



