"""AmneziaVPN settings OffRoute needs, checked and fixed for the user (no manual setup).

Amnezia keeps settings in ~/Library/Preferences/org.amneziavpn.AmneziaVPN.plist. It holds them in memory and writes
them back on quit, so to change them it is closed first, then started again. A missing Kill Switch key means ON
(isKillSwitchEnabled() defaults to true in amnezia-client secureAppSettingsRepository.cpp).
"""

from __future__ import annotations

import plistlib
import subprocess
import time
from pathlib import Path

DOMAIN = "org.amneziavpn.AmneziaVPN"
PLIST = Path.home() / f"Library/Preferences/{DOMAIN}.plist"
WANT = (("Conf.killSwitchEnabled", "-bool", "false"),
        ("Conf.sitesSplitTunnelingEnabled", "-bool", "true"),
        ("Conf.routeMode", "-int", "1"),
        ("Conf.autoConnect", "-bool", "true"))  # after the restart it reconnects by itself


def read() -> dict | None:
    try:
        with PLIST.open("rb") as f:
            return plistlib.load(f)
    except (OSError, plistlib.InvalidFileException):
        return None


def checks() -> list[dict]:
    a = read()
    if a is None:
        return [{"ok": False, "text": "AmneziaVPN не найдена (нужна версия с сайта amnezia.org)"}]
    ks_off = a.get("Conf.killSwitchEnabled", True) in (False, 0)
    split = bool(a.get("Conf.sitesSplitTunnelingEnabled"))
    mode = int(a.get("Conf.routeMode", 0) or 0)
    return [
        {"ok": ks_off, "text": "Kill Switch выключен" if ks_off else "Kill Switch включён"},
        {"ok": split, "text": "Раздельное туннелирование сайтов включено"},
        {"ok": split and mode == 1, "text": "Режим «Только адреса из списка»"},
    ]


def needs_fix() -> bool:
    return read() is not None and not all(c["ok"] for c in checks())


def running() -> bool:
    return subprocess.run(["pgrep", "-x", "AmneziaVPN"], capture_output=True).returncode == 0


def fix() -> str:
    if read() is None:
        return "AmneziaVPN не найдена"
    was_running = running()
    if was_running:
        subprocess.run(["osascript", "-e", f'tell application id "{DOMAIN}" to quit'], capture_output=True)
        for _ in range(40):
            if not running():
                break
            time.sleep(0.25)
        else:
            subprocess.run(["pkill", "-x", "AmneziaVPN"], capture_output=True)
            time.sleep(1)
    for key, kind, val in WANT:
        subprocess.run(["defaults", "write", DOMAIN, key, kind, val], capture_output=True)
    if was_running:
        subprocess.run(["open", "-g", "-b", DOMAIN], capture_output=True)
    return "Настройки Амнезии исправлены"
