"""Paths shared by the service (root) and the window/menu (user), and the command socket.

The service keeps its memory in a root-owned folder: nobody but root can write there, so no symlink or file
swap by a user process can make root write or execute something else.
The window and the menu only READ those files; commands go through a Unix socket whose peer uid is checked.
"""

from __future__ import annotations

import json
import os
import socket
import struct
from pathlib import Path

ROOT_DATA = Path("/Library/Application Support/OffRoute")  # root:wheel 755
STATE = ROOT_DATA / "state.json"
STATUS = ROOT_DATA / "status.json"
LOG = ROOT_DATA / "offroute.log"
GOOGLE_CACHE = ROOT_DATA / "google-ranges.json"
LOG_DIR = Path("/Library/Logs/OffRoute")  # launchd stderr of the service
SOCK = "/var/run/offroute.sock"

USER_DATA = Path.home() / "Library/Application Support/OffRoute"  # window/menu own small things (pid, consent)
OLD_USER_DATA = Path.home() / "Library/Application Support/vpn-autoroute"  # versions before 0.3

OPS = {"enable", "disable", "autostart_on", "autostart_off", "group_on", "group_off",
       "remove", "direct", "undirect", "add"}
MAX_MSG = 4096

SOL_LOCAL, LOCAL_PEERCRED = 0, 0x001  # <sys/un.h>


def peer_uid(conn: socket.socket) -> int | None:
    """uid of the process on the other end of a Unix socket (struct xucred: version u_int, uid uid_t, ...)."""
    try:
        raw = conn.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, 76)
        return struct.unpack_from("I", raw, 4)[0]
    except OSError:
        return None


def console_uid() -> int | None:
    try:
        return os.stat("/dev/console").st_uid
    except OSError:
        return None


def send(op: str, site: str = "") -> bool:
    """Window/menu → service. False if the service is not running."""
    if op not in OPS:
        return False
    msg = json.dumps({"op": op, "site": site}).encode()[:MAX_MSG]
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect(SOCK)
        s.sendall(msg + b"\n")
        return s.recv(16).startswith(b"ok")
    except OSError:
        return False
    finally:
        s.close()


def read_json(p: Path) -> dict:
    try:
        if p.stat().st_size > 5_000_000:
            return {}
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {}


def tail(p: Path, n: int) -> list[str]:
    """Last n lines without reading the whole log."""
    try:
        with p.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 64 * 1024))
            return f.read().decode("utf-8", "replace").splitlines()[-n:]
    except OSError:
        return []
