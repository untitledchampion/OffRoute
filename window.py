"""The OffRoute window: on/off, autostart, AmneziaVPN settings check, sites through the VPN.

Runs as the user. Reads the service's files (root-owned, read-only for us) and the AmneziaVPN settings;
sends commands to the service through its socket.
"""

import json
import os
import plistlib
import time
from pathlib import Path

import webview

import ipc

HERE = Path(__file__).resolve().parent  # code and resources
AGENT = Path.home() / "Library/LaunchAgents/local.vpn-autoroute.menu.plist"
PREFS = ipc.USER_DATA / "ui.json"  # the user's own answers (consent to change Amnezia)
PIDFILE = ipc.USER_DATA / ".window.pid"
read_json = ipc.read_json


def prefs() -> dict:
    return read_json(PREFS)


def set_pref(key: str, value) -> None:
    ipc.USER_DATA.mkdir(parents=True, exist_ok=True)
    p = prefs()
    p[key] = value
    PREFS.write_text(json.dumps(p))


def amnezia_checks() -> list[dict]:
    import amnezia
    return amnezia.checks()


class Api:
    def state(self) -> dict:
        st, status = read_json(ipc.STATE), read_json(ipc.STATUS)
        sites = [{"name": n, **s} for n, s in st.get("sites", {}).items() if isinstance(s, dict)]
        sites.sort(key=lambda s: s.get("last") or s.get("added") or "", reverse=True)
        lines = [ln for ln in ipc.tail(ipc.LOG, 200) if " + " in ln or " - " in ln]
        last = lines[-1][11:] if lines else ""
        import amnezia
        return {
            "installed": Path("/Library/LaunchDaemons/local.vpn-autoroute.plist").exists(),
            "amnezia_bad": amnezia.needs_fix(),
            "amnezia_consent": prefs().get("amnezia_consent"),
            "alive": time.time() - status.get("updated", 0) < 15,
            "tunnel": status.get("tunnel"),
            "enabled": st.get("enabled", True),
            "autostart": st.get("autostart", True),
            "sites": sites,
            "checks": amnezia_checks(),
            "last": last,
        }

    def send(self, op: str, site: str) -> bool:
        return ipc.send(op, site)

    def set_amnezia_consent(self, yes: bool) -> str:
        """Asked once, in the window: change Amnezia's settings for OffRoute (Kill Switch off, split tunneling
        «only listed», auto-connect)? Not repeated on its own afterwards."""
        set_pref("amnezia_consent", bool(yes))
        if not yes:
            return ""
        import amnezia
        return amnezia.fix() if amnezia.needs_fix() else ""

    def uninstall(self) -> bool:
        import main  # packaged app only
        ok = main.uninstall()
        if ok:
            for win in webview.windows:
                win.destroy()
        return ok

    def set_autostart(self, on: bool) -> bool:
        self.send("autostart_on" if on else "autostart_off", "")
        try:  # the menu bar icon starts at login only when autostart is on
            with AGENT.open("rb") as f:
                p = plistlib.load(f)
            p["RunAtLoad"] = bool(on)
            with AGENT.open("wb") as f:
                plistlib.dump(p, f)
        except OSError:
            pass
        return True


def set_dock_icon() -> None:
    try:
        from AppKit import NSApplication, NSImage
        img = NSImage.alloc().initWithContentsOfFile_(str(HERE / "icon/app.png"))
        NSApplication.sharedApplication().performSelectorOnMainThread_withObject_waitUntilDone_(
            "setApplicationIconImage:", img, False)
    except Exception:  # noqa: BLE001
        pass


def main() -> None:
    ipc.USER_DATA.mkdir(parents=True, exist_ok=True)
    PIDFILE.write_text(str(os.getpid()))
    try:
        webview.create_window("OffRoute", str(HERE / "ui.html"), js_api=Api(),
                              width=380, height=720, min_size=(340, 520))
        webview.start(set_dock_icon)
    finally:
        PIDFILE.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
