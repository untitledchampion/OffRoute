"""Menu bar icon for vpn-autoroute: which sites go through the VPN, remove / keep direct / add, recent events.

Reads state.json, status.json and autoroute.log written by the service; sends commands as cmd/*.json files.
"""

import json
import os
import subprocess
import time
from pathlib import Path

import rumps

import ipc

HERE = Path(__file__).resolve().parent  # code and resources
STATE, STATUS, LOG = ipc.STATE, ipc.STATUS, ipc.LOG
BASE = ["Telegram", "Claude"]


read_json, tail = ipc.read_json, ipc.tail


def short_time(iso: str) -> str:
    return iso.replace("T", " ")[5:16] if iso else ""


class App(rumps.App):
    def __init__(self) -> None:
        super().__init__("", icon=str(HERE / "icon/menubarTemplate.png"), template=True, quit_button=None)
        try:  # menu bar only: no Python icon in the Dock
            from AppKit import NSApplication
            NSApplication.sharedApplication().setActivationPolicy_(1)  # NSApplicationActivationPolicyAccessory
        except Exception:  # noqa: BLE001
            pass
        self.sig = None
        self.refresh(None)

    def send(self, op: str, site: str) -> None:
        if not ipc.send(op, site):
            rumps.notification("OffRoute", "", "Служба не отвечает")
            return
        rumps.notification("OffRoute", "", {"remove": f"{site}: убираю из VPN",
                                                 "direct": f"{site}: всегда напрямую",
                                                 "undirect": f"{site}: снова может идти через VPN",
                                                 "add": f"{site}: добавляю в VPN"}[op])
        self.sig = None

    def open_window(self, _=None) -> None:
        app = os.environ.get("VPN_AUTOROUTE_APP")
        if app:  # packaged: macOS brings the open window to the front or starts the app
            subprocess.Popen(["open", app])
            return
        pid = (ipc.USER_DATA / ".window.pid")
        try:
            os.kill(int(pid.read_text()), 0)
            return  # already open
        except (OSError, ValueError):
            pass
        subprocess.Popen([str(HERE / ".venv/bin/python"), str(HERE / "window.py")])

    def ask_add(self, _) -> None:
        w = rumps.Window("Сайт или IP-адрес, который пустить через VPN:", "Добавить сайт",
                         default_text="", ok="Добавить", cancel="Отмена", dimensions=(260, 24))
        r = w.run()
        if r.clicked and r.text.strip():
            self.send("add", r.text.strip())

    @rumps.timer(3)
    def refresh(self, _) -> None:
        st, status = read_json(STATE), read_json(STATUS)
        alive = time.time() - status.get("updated", 0) < 15
        tun = status.get("tunnel")
        sites = st.get("sites", {})
        if "learned" in st:  # state of the first version
            sites = {f"?{k.split('/')[0]}": {"ips": [k.split('/')[0]], "added": v.get("added", "")}
                     for k, v in st["learned"].items()}
        direct = st.get("direct", [])
        log_lines = tail(LOG, 10)

        self.title = "" if alive and tun else (" ·" if alive else " !")  # helmet icon; mark only when something is wrong
        sig = (json.dumps(sites, sort_keys=True), tuple(direct), alive, tun, tuple(log_lines))
        if sig == self.sig:
            return
        self.sig = sig

        m = [rumps.MenuItem("Открыть окно", callback=self.open_window), None]
        if not alive:
            m.append(rumps.MenuItem("Служба не работает — запустите install.sh"))
        elif not tun:
            m.append(rumps.MenuItem("VPN выключен"))
        else:
            m.append(rumps.MenuItem(f"VPN подключён ({tun}); всегда через VPN: {', '.join(BASE)}"))
        m.append(None)
        m.append(rumps.MenuItem(f"Сайты через VPN: {len(sites)}"))
        for name in sorted(sites, key=lambda n: (n.startswith("?"), n)):
            s = sites[name]
            label = (name[1:] + "  (сайт неизвестен)") if name.startswith("?") else name
            item = rumps.MenuItem(f"   {label}   [{len(s.get('ips', []))}]")
            for ip in s.get("ips", []):
                item.add(rumps.MenuItem(ip))
            hosts = [h for h in s.get("hosts", []) if h != name]
            if hosts:
                item.add(rumps.MenuItem("имена: " + ", ".join(hosts[:5]) + (" …" if len(hosts) > 5 else "")))
            item.add(rumps.MenuItem(f"программа: {s.get('app') or '—'}"))
            item.add(rumps.MenuItem(f"добавлен: {short_time(s.get('added', ''))}"))
            item.add(None)
            item.add(rumps.MenuItem("Убрать из VPN", callback=lambda _, n=name: self.send("remove", n)))
            if not name.startswith("?"):
                item.add(rumps.MenuItem("Всегда напрямую", callback=lambda _, n=name: self.send("direct", n)))
            m.append(item)
        m.append(rumps.MenuItem("Добавить сайт…", callback=self.ask_add))
        if direct:
            m.append(None)
            d = rumps.MenuItem(f"Всегда напрямую: {len(direct)}")
            for name in sorted(direct):
                sub = rumps.MenuItem(name)
                sub.add(rumps.MenuItem("Снова разрешить VPN", callback=lambda _, n=name: self.send("undirect", n)))
                d.add(sub)
            m.append(d)
        m.append(None)
        ev = rumps.MenuItem("Последние события")
        for line in reversed(log_lines):
            ev.add(rumps.MenuItem(line[5:] if line[:4].isdigit() else line))
        m.append(ev)
        m.append(rumps.MenuItem("Открыть журнал", callback=lambda _: subprocess.run(["open", "-a", "Console", str(LOG)])))
        m.append(None)
        m.append(rumps.MenuItem("Выйти из меню (служба продолжит работать)", callback=lambda _: rumps.quit_application()))
        self.menu.clear()
        self.menu = m


if __name__ == "__main__":
    App().run()
