"""Entry point of the packaged app (vpn-autoroute.app/Contents/MacOS/vpn-autoroute runs this).

  (no args)     the window; on first start installs the service (asks for the admin password once)
  --menu        the menu bar icon (started at login by a LaunchAgent)
  --service     the service (root, started by a LaunchDaemon)
  --uninstall   remove the service and the menu icon
"""

from __future__ import annotations

import os
import plistlib
import shlex
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent  # .app/Contents/Resources/app
APP = HERE.parents[2]  # .app
EXE = APP / "Contents/MacOS/OffRoute"
LABEL = "local.vpn-autoroute"
DAEMON = Path(f"/Library/LaunchDaemons/{LABEL}.plist")
AGENT = Path.home() / f"Library/LaunchAgents/{LABEL}.menu.plist"

sys.path.insert(0, str(HERE))


def admin(cmd: str, prompt: str) -> bool:
    """Run a shell command as root through the standard macOS password dialog."""
    esc = cmd.replace("\\", "\\\\").replace('"', '\\"')
    script = f'do shell script "{esc}" with prompt "{prompt}" with administrator privileges'
    return subprocess.run(["osascript", "-e", script], capture_output=True).returncode == 0


def installed() -> bool:
    return DAEMON.exists()


def install_menu() -> None:
    AGENT.parent.mkdir(parents=True, exist_ok=True)
    autostart = True
    if AGENT.exists():
        try:
            with AGENT.open("rb") as f:
                autostart = plistlib.load(f).get("RunAtLoad", True)
        except (OSError, plistlib.InvalidFileException):
            pass
    p = {
        "Label": f"{LABEL}.menu",
        "ProgramArguments": [str(EXE), "--menu"],
        "EnvironmentVariables": {"VPN_AUTOROUTE_APP": str(APP)},
        "RunAtLoad": autostart,
        "KeepAlive": {"SuccessfulExit": False},
        "StandardErrorPath": "/dev/null",
    }
    uid = os.getuid()
    subprocess.run(["launchctl", "bootout", f"gui/{uid}/{LABEL}.menu"], capture_output=True)
    with AGENT.open("wb") as f:
        plistlib.dump(p, f)
    # bootout finishes asynchronously; bootstrap right after it fails with an I/O error, so retry
    import time
    for _ in range(10):
        if subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", str(AGENT)], capture_output=True).returncode == 0:
            break
        time.sleep(0.5)
    subprocess.run(["launchctl", "kickstart", f"gui/{uid}/{LABEL}.menu"], capture_output=True)


def uninstall() -> bool:
    """Stop the service (it takes its pf rule and routes away on SIGTERM), then remove everything it installed."""
    uid = os.getuid()
    q = shlex.quote
    ok = admin(" ; ".join([
        f"launchctl bootout system/{LABEL} 2>/dev/null",
        "sleep 1",
        "pfctl -a com.apple/250.vpn-autoroute -F all 2>/dev/null",  # in case the service could not
        f"rm -f {q(str(DAEMON))} /var/run/offroute.sock",
        "rm -rf '/Library/Application Support/OffRoute' /Library/Logs/OffRoute",
        "pkgutil --forget local.vpn-autoroute.pkg >/dev/null 2>&1",
    ]), "OffRoute удаляет свою службу.")
    if ok:
        subprocess.run(["launchctl", "bootout", f"gui/{uid}/{LABEL}.menu"], capture_output=True)
        AGENT.unlink(missing_ok=True)
    return ok


def main() -> None:
    arg = next((a for a in sys.argv[1:] if not a.startswith("-psn")), "")
    os.environ["VPN_AUTOROUTE_APP"] = str(APP)
    if arg == "--service":
        import autoroute
        sys.argv = ["autoroute", "run"]
        autoroute.main()
    elif arg == "--menu":
        import menubar
        menubar.App().run()
    elif arg == "--selftest":
        import amnezia, autoroute, ipc, menubar, sni, window  # noqa: F401
        print("ok", sys.version.split()[0], APP)
    elif arg == "--fix-amnezia":
        import amnezia
        if amnezia.needs_fix():
            print(amnezia.fix())
    elif arg == "--uninstall":
        uninstall()
    else:
        if installed():
            install_menu()
        import window  # without the service the window says how to install it (only the .pkg installs it)
        window.main()


if __name__ == "__main__":
    main()
