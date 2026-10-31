# trust.py
"""Resolve helper binaries without trusting a writable PATH entry.

The manager runs as root for every system write and pipes private keys into
`wg`/`qrencode`. A root process that inherits a user-writable PATH entry could
execute a planted binary with key material on stdin. Root callers therefore
accept only regular, root-owned executables that are not group/world-writable.
Non-root callers keep the historical PATH behaviour: they cannot escalate
through a PATH they already control.
"""
import os
import shutil
import stat

from .constants import SYSROOT


def which_trusted(name):
    """Return the PATH-resolved binary, or None when a root caller must not use it."""
    exe = shutil.which(name)
    if not exe:
        return None
    try:
        st = os.stat(exe)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    try:
        euid = os.geteuid()
    except AttributeError:
        euid = 1000
    # SYSROOT is the test seam: CI root runs execute fake binaries from a temp
    # tree, so ownership checks are intentionally relaxed there only.
    if euid == 0 and not SYSROOT and (st.st_uid != 0 or st.st_mode & 0o022):
        return None
    return exe
