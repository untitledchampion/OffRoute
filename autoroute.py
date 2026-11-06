#!/usr/bin/env python3
"""vpn-autoroute: send only chosen sites through the VPN tunnel and learn blocked ones on the fly.

AmneziaVPN runs in split mode «only listed addresses through VPN» (its list: Telegram, Claude).
This service, as root, without reconnecting the VPN:
  * keeps the base networks (Telegram, Claude) and the learned sites routed into the tunnel;
  * watches TCP connections (nettop): stuck in SynSent, or HTTPS with the request sent and 0 bytes back;
    if such an address works through the tunnel, it is added — to the tunnel's AllowedIPs (AmneziaWG
    control socket) and as a /32 route;
  * names each address by the site the browser asked for (TLS SNI read with tcpdump) and the program;
  * re-adds everything after a VPN reconnect;
  * takes commands from the window and the menu through a Unix socket (peer uid checked).

Memory (root-owned, /Library/Application Support/OffRoute): state.json, status.json, offroute.log.

Commands:
  check              no root: tunnel, where base networks go, a few probes
  run                root: the service (Ctrl+C to stop)
  add SITE|IP        ask the running service to add a site
  remove SITE        ask the running service to remove a site
  list
"""

from __future__ import annotations

import ipaddress
import json
import os
import queue
import re
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ipc  # noqa: E402
from sni import SniMap, SniWatcher  # noqa: E402

ROOT_DATA, STATE, STATUS, LOG, GOOGLE_CACHE = ipc.ROOT_DATA, ipc.STATE, ipc.STATUS, ipc.LOG, ipc.GOOGLE_CACHE
LOG_MAX = 1_000_000
HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}\.)*[a-z0-9-]{1,63}$")
MAX_SITES = 5000

# Official lists: https://core.telegram.org/resources/cidr.txt , https://platform.claude.com/docs/en/api/ip-addresses
BASE = {
    "Telegram": [
        "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22",
        "91.108.56.0/22", "91.105.192.0/23", "149.154.160.0/20", "185.76.151.0/24",
    ],
    "Claude": ["160.79.104.0/23", "153.61.224.0/22", "35.190.46.17/32"],
}

IP_BOUND_IF = 25  # macOS: pin a socket to an interface regardless of the routing table
POLL = 2.0
STUCK = 3.0  # a stalled connection older than this is a candidate
PROBE_TIMEOUT = 4.0
RETEST_AFTER = 3600  # after an address was handled
RETRY_FAILED = 90  # an address that did not work through the VPN either: try again soon (the server may recover)

NEVER = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3",
)]
SECOND_LEVEL = {"co", "com", "net", "org", "gov", "edu", "ac", "msk", "spb"}


# ---------- files written by root: only in the root-owned folder, never following a link ----------

def ensure_root_data() -> None:
    """/Library/Application Support/OffRoute must be a real root:wheel 755 folder. If something else sits there
    (a link, a user-owned folder), move it aside instead of writing through it."""
    for d in (ROOT_DATA, ipc.LOG_DIR):
        try:
            st = os.lstat(d)
            if not (os.path.isdir(d) and not os.path.islink(d) and st.st_uid == 0 and not st.st_mode & 0o022):
                os.rename(d, f"{d}.suspicious-{int(time.time())}")
                raise FileNotFoundError
        except FileNotFoundError:
            os.makedirs(d, mode=0o755, exist_ok=True)
        os.chown(d, 0, 0)
        os.chmod(d, 0o755)


def safe_write(path: Path, text: str) -> None:
    """Atomic write: a new file created exclusively (O_EXCL, O_NOFOLLOW) next to the target, then rename."""
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


_log_lock = threading.Lock()


def log(msg: str) -> None:
    msg = "".join(ch if ch.isprintable() else " " for ch in msg)[:500]  # names from the network: no fake lines
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}"
    print(line, flush=True)
    if os.geteuid() != 0:
        return
    with _log_lock:
        try:
            if os.lstat(LOG).st_size > LOG_MAX:
                os.replace(LOG, f"{LOG}.1")
        except FileNotFoundError:
            pass
        try:
            fd = os.open(LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, "a") as f:
                f.write(line + "\n")
        except OSError:
            pass


def clean_host(host: str | None) -> str | None:
    """A site name from the network or a command: lowercase letters, digits, dots, dashes; else nothing."""
    if not host:
        return None
    host = host.strip().rstrip(".").lower()
    return host if len(host) <= 253 and HOST_RE.match(host) else None


def sh(*args: str) -> str:
    return subprocess.run(args, capture_output=True, text=True).stdout


def now_s() -> str:
    return datetime.now().isoformat(timespec="seconds")


def site_of(host: str) -> str:  # host is already clean_host()-ed
    """Registrable part of a host name: rr3---sn-x.googlevideo.com -> googlevideo.com, x.co.uk -> x.co.uk."""
    parts = host.strip(".").lower().split(".")
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ---------- state ----------

def valid_ip(ip: object) -> str | None:
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    return str(a) if a.version == 4 and not skip(str(a)) else None


def validate(raw: object) -> dict:
    """Whatever is on disk, keep only well-formed fields: a broken or crafted file must neither crash the service
    (endless launchd restarts) nor route the whole internet somewhere."""
    raw = raw if isinstance(raw, dict) else {}
    st: dict = {"sites": {}, "direct": []}
    for name, s in list((raw.get("sites") or {}).items())[:MAX_SITES] if isinstance(raw.get("sites"), dict) else []:
        if not isinstance(s, dict) or not isinstance(name, str):
            continue
        key = name if name.startswith("?") and valid_ip(name[1:]) else clean_host(name)
        ips = [i for i in (valid_ip(x) for x in (s.get("ips") or [])[:256]) if i]
        if not key or not ips:
            continue
        st["sites"][key] = {
            "ips": ips,
            "hosts": [h for h in (clean_host(x) for x in (s.get("hosts") or [])[:32] if isinstance(x, str)) if h],
            "app": str(s.get("app") or "")[:64],
            "added": str(s.get("added") or now_s())[:32],
            "last": str(s.get("last") or "")[:32],
        }
    st["direct"] = [h for h in (clean_host(x) for x in (raw.get("direct") or [])[:MAX_SITES] if isinstance(x, str)) if h]
    st["enabled"] = raw.get("enabled", True) is not False
    st["autostart"] = raw.get("autostart", True) is not False
    # YouTube is always routed: it is throttled, not blocked, so it cannot be found automatically (0.3.2)
    st["groups"] = {k: True for k in GROUPS}
    st["schema"] = int(raw.get("schema", 1)) if isinstance(raw.get("schema"), int) else 1
    return st


def load() -> dict:
    try:
        raw = json.loads(STATE.read_text()) if STATE.exists() else {}
    except (OSError, ValueError):
        try:
            os.replace(STATE, f"{STATE}.bad")
        except OSError:
            pass
        raw = {}
    return validate(raw)


def import_old_state(old_dir: str | None) -> None:
    """0.2 kept its memory in the user's folder. Take it over once, read-only and validated."""
    if STATE.exists() or not old_dir:
        return
    old = Path(old_dir) / "state.json"
    try:
        fd = os.open(old, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            raw = json.loads(f.read(5_000_000))
    except (OSError, ValueError):
        return
    st = validate(raw)
    save(st)
    log(f"перенесена память версии 0.2: сайтов {len(st['sites'])}")


def save(st: dict) -> None:
    index_ips(st)
    safe_write(STATE, json.dumps({k: v for k, v in st.items() if not k.startswith("_")}, indent=2, ensure_ascii=False))


# Optional groups switched on in the window. YouTube is throttled in Russia rather than blocked (data trickles,
# often over QUIC/UDP), so stall detection does not see it: route Google's official networks instead.
GOOGLE_URL = "https://www.gstatic.com/ipranges/goog.json"  # https://support.google.com/a/answer/10026322


def sane_nets(items: object) -> list[str]:
    """IPv4 networks no wider than /8 and outside private ranges: a crafted list must not route the whole internet."""
    out = []
    for x in items if isinstance(items, list) else []:
        try:
            n = ipaddress.ip_network(str(x), strict=False)
        except ValueError:
            continue
        if n.version == 4 and n.prefixlen >= 8 and not any(n.overlaps(b) for b in NEVER):
            out.append(str(n))
    return out[:2000]


def google_ranges() -> list[str]:
    cache = GOOGLE_CACHE
    try:
        if cache.exists() and time.time() - cache.stat().st_mtime < 86400:
            nets = sane_nets(json.loads(cache.read_text()))
            if nets:
                return nets
    except (OSError, ValueError):
        pass
    try:
        import urllib.request
        d = json.loads(urllib.request.urlopen(GOOGLE_URL, timeout=10).read(2_000_000))
        nets = sane_nets([x.get("ipv4Prefix") for x in d.get("prefixes", []) if x.get("ipv4Prefix")])
        if nets:
            if os.geteuid() == 0:
                safe_write(cache, json.dumps(nets))
            return nets
    except Exception as e:  # noqa: BLE001 — no network yet: use the old cache
        log(f"не скачал список сетей Google: {e}")
    try:
        return sane_nets(json.loads(cache.read_text()))
    except (OSError, ValueError):
        return []


GROUPS = {"YouTube": google_ranges}


def group_nets(st: dict) -> list[str]:
    nets = [n for group in BASE.values() for n in group]
    if st.get("enabled", True):
        for name, fn in GROUPS.items():
            if st.get("groups", {}).get(name):
                cache = st.setdefault("_group_cache", {})
                if not cache.get(name):
                    cache[name] = fn()
                nets += cache[name]
    return nets


def all_networks(st: dict) -> list[str]:
    nets = group_nets(st)
    if not st.get("enabled", True):
        return nets
    for s in st["sites"].values():
        nets += [f"{ip}/32" for ip in s["ips"]]
    return nets


def site_by_ip(st: dict, ip: str) -> str | None:
    for name, s in st["sites"].items():
        if ip in s["ips"]:
            return name
    return None


# ---------- interfaces and routes ----------

UAPI_DIR = "/var/run/amneziawg"


def tunnel_iface() -> str | None:
    """The AmneziaWG tunnel: a utun with an IPv4 address AND an AmneziaWG control socket. Tailscale, a work VPN
    or any other utun is not ours to steer."""
    for name in sh("ifconfig", "-l").split():
        if name.startswith("utun") and os.path.exists(f"{UAPI_DIR}/{name}.sock"):
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", sh("ifconfig", name))
            if m and not m.group(1).startswith("169.254."):
                return name
    return None


def tunnel_ip(iface: str) -> str | None:
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", sh("ifconfig", iface))
    return m.group(1) if m else None


def physical_iface() -> str:
    """The interface ordinary traffic leaves by. Ask the routing table for a Russian address that is never in
    our lists; the first «default» line of netstat may be a stale or second interface (Wi-Fi + Ethernet,
    hotspot), and probing through it made every site look blocked."""
    via = route_iface("77.88.55.242")
    if via and not via.startswith("utun"):
        return via
    for line in sh("netstat", "-rn", "-f", "inet").splitlines():
        parts = line.split()
        if parts and parts[0] == "default" and not parts[-1].startswith(("utun", "ipsec", "ppp")) and "I" not in parts[2]:
            return parts[-1]
    return "en0"


def route_iface(ip: str) -> str | None:
    m = re.search(r"interface: (\S+)", sh("route", "-n", "get", ip))
    return m.group(1) if m else None


def net_probe_ip(net: str) -> str:
    n = ipaddress.ip_network(net, strict=False)
    return str(n.network_address if n.prefixlen >= 31 else n.network_address + 1)


def route_add(net: str, iface: str) -> bool:
    n = ipaddress.ip_network(net, strict=False)
    if n.prefixlen == 32:
        args = ["route", "-n", "add", "-host", str(n.network_address), "-interface", iface]
    else:
        args = ["route", "-n", "add", "-net", str(n), "-interface", iface]
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0 and "File exists" in r.stderr:
        subprocess.run(["route", "-n", "change", *args[3:]], capture_output=True, text=True)
        return True
    return r.returncode == 0


def route_delete_host(ip: str) -> None:
    subprocess.run(["route", "-n", "delete", "-host", ip], capture_output=True, text=True)


def has_scoped_default(iface: str) -> bool:
    for line in sh("netstat", "-rn", "-f", "inet").splitlines():
        p = line.split()
        if p and p[0] == "default" and p[-1] == iface and "I" in p[2]:
            return True
    return False


def default_gw(phys: str) -> str | None:
    """Gateway of the primary (unscoped) default route via phys."""
    for ln in sh("netstat", "-rn", "-f", "inet").splitlines():
        p = ln.split()
        if p[:1] == ["default"] and p[-1] == phys and "I" not in p[2]:
            return p[1]
    return None


def scoped_gw(phys: str) -> str | None:
    for ln in sh("netstat", "-rn", "-f", "inet").splitlines():
        p = ln.split()
        if p[:1] == ["default"] and p[-1] == phys and "I" in p[2]:
            return p[1]
    return None


def ensure_direct_scoped_default(phys: str) -> None:
    """A default route scoped to the direct interface. Without it, once everything is routed into the tunnel
    (0/1 + 128/1, «Выключено» or the no-direct fallback), a socket pinned to en0 still follows those routes and
    every direct probe fails. After a Wi-Fi change the gateway differs: replace it."""
    gw = default_gw(phys)
    cur = scoped_gw(phys)
    if not gw or cur == gw:
        return
    if cur:
        subprocess.run(["route", "-n", "delete", "-ifscope", phys, "default"], capture_output=True, text=True)
    subprocess.run(["route", "-n", "add", "-ifscope", phys, "default", gw], capture_output=True, text=True)


def ensure_scoped_default(iface: str) -> None:
    """A default route scoped to the tunnel: used only by sockets pinned to it (our probes); ordinary traffic
    is not affected."""
    if not has_scoped_default(iface):
        subprocess.run(["route", "-n", "add", "-ifscope", iface, "default", "-interface", iface],
                       capture_output=True, text=True)


# ---------- AmneziaWG control socket ----------
# In «only listed» mode Amnezia sets WireGuard AllowedIPs to its list: the tunnel drops packets to anything else.
# AllowedIPs of a live tunnel can be extended through the userspace API socket, without reconnecting.

def uapi(iface: str, request: str) -> str:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect(f"{UAPI_DIR}/{iface}.sock")
        s.sendall(request.encode())
        buf = b""
        while not buf.endswith(b"\n\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return buf.decode()
    finally:
        s.close()


def _covered_by(net: ipaddress.IPv4Network, allowed: list) -> bool:
    """net inside one of allowed. allowed is sorted widest first; checks only networks that can contain it."""
    for a in allowed:
        if a.prefixlen > net.prefixlen:
            break
        if net.subnet_of(a):
            return True
    return False


def wg_allow(iface: str, nets: list[str]) -> bool:
    """Make sure the tunnel accepts these networks. False when the tunnel cannot be told (no socket, VPN went away):
    then routes and pf must not be touched, or the sites go neither directly nor through the VPN."""
    try:
        key, allowed = None, []
        for line in uapi(iface, "get=1\n\n").splitlines():
            if line.startswith("public_key="):
                key = line.split("=", 1)[1]
            elif line.startswith("allowed_ip=") and key:
                try:
                    a = ipaddress.ip_network(line.split("=", 1)[1], strict=False)
                except ValueError:
                    continue
                if a.version == 4:
                    allowed.append(a)
        if not key:
            return False
        allowed.sort(key=lambda a: a.prefixlen)
        exact = {str(a) for a in allowed}
        missing = []
        for n in nets:
            net = ipaddress.ip_network(n, strict=False)
            if net.version == 4 and str(net) not in exact and not _covered_by(net, allowed):
                missing.append(str(net))
        if not missing:
            return True
        resp = uapi(iface, f"set=1\npublic_key={key}\n" + "".join(f"allowed_ip={n}\n" for n in missing) + "\n")
    except OSError as e:
        log(f"нет доступа к управлению туннелем {iface}: {e}")
        return False
    if "errno=0" not in resp:
        log(f"туннель не принял адреса: {resp.strip()[:200]}")
        return False
    return True


def routes_on(iface: str) -> set[str]:
    """Networks routed to iface, read from ONE netstat call (not a `route get` per network:
    with thousands of sites that would be thousands of processes every 10 seconds)."""
    out = set()
    for line in sh("netstat", "-rn", "-f", "inet").splitlines():
        p = line.split()
        if len(p) < 4 or p[-1] != iface or p[0] == "default":
            continue
        dest = p[0]
        try:
            if "/" in dest:
                addr, plen = dest.split("/")
                octs = addr.split(".")
                out.add(str(ipaddress.ip_network(".".join(octs + ["0"] * (4 - len(octs))) + "/" + plen, strict=False)))
            elif "H" in p[2]:
                out.add(f"{ipaddress.ip_address(dest)}/32")
            else:  # netstat shortens 130.211.0.0/16 to "130.211"
                octs = dest.split(".")
                out.add(str(ipaddress.ip_network(".".join(octs + ["0"] * (4 - len(octs))) + f"/{8 * len(octs)}", strict=False)))
        except ValueError:
            continue
    return out


# ---------- cutting old direct connections ----------
# A route only steers NEW connections. Chrome keeps its old direct connections to a site (across tabs) and goes
# on waiting on them. A pf rule answers any packet to a VPN-routed network that still leaves through the direct
# interface with a reset: the program reconnects at once, and the new connection takes the tunnel.
# Rules live in our own anchor under com.apple/*, which the stock /etc/pf.conf already loads.

PF_ANCHOR = "com.apple/250.vpn-autoroute"
_pf_token: str | None = None


def wg_endpoint(iface: str) -> str | None:
    try:
        for line in uapi(iface, "get=1\n\n").splitlines():
            if line.startswith("endpoint="):
                return line.split("=", 1)[1].rsplit(":", 1)[0].strip("[]")
    except OSError:
        pass
    return None


def pf_cut_direct(phys: str, tun: str, nets: list[str], all_vpn: bool = False) -> None:
    global _pf_token
    if not re.fullmatch(r"[a-z]+[0-9]+", phys):
        return
    if _pf_token is None:  # keep pf enabled while we run (reference-counted; Amnezia may use it too)
        r = subprocess.run(["pfctl", "-E"], capture_output=True, text=True)
        m = re.search(r"Token : (\d+)", r.stderr + r.stdout)
        _pf_token = m.group(1) if m else ""
    endpoint = wg_endpoint(tun)
    rules = ""
    endpoint_ok = False
    if endpoint:
        try:
            endpoint_ok = ipaddress.ip_address(endpoint).version == 4
        except ValueError:
            pass
    if endpoint_ok:
        rules += f"pass out quick on {phys} proto {{ tcp udp }} to {endpoint}\n"
    all_vpn = all_vpn and endpoint_ok  # never cut everything without knowing the VPN server: that would cut the VPN
    rules += f"block return out quick on {phys} proto {{ tcp udp }} to <vpnauto>\n"
    if all_vpn:
        # «весь трафик через VPN»: routes only steer NEW connections; connections opened directly before (Chrome keeps
        # them, QUIC too) would go on working past the VPN. Cut everything that still leaves directly, except the VPN
        # server, the local network, DHCP and our own direct-path check (ya.ru) — then programs reconnect through
        # the tunnel. The tunnel is IPv4-only, so IPv6 must not leak past it either.
        rules += (f"pass out quick on {phys} inet to {{ 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 "
                  f"224.0.0.0/4 255.255.255.255 }}\n"
                  f"pass out quick on {phys} proto udp from any port 68 to any port 67\n"
                  f"pass out quick on {phys} proto tcp to 77.88.55.242 port 443\n"
                  f"block return out quick on {phys} inet proto {{ tcp udp }} all\n"
                  f"block return out quick on {phys} inet6 proto {{ tcp udp }} from any to ! fe80::/10\n")
    subprocess.run(["pfctl", "-a", PF_ANCHOR, "-f", "-"], input=rules, capture_output=True, text=True)
    subprocess.run(["pfctl", "-a", PF_ANCHOR, "-t", "vpnauto", "-T", "replace", "-f", "-"],
                   input="\n".join(nets) + "\n", capture_output=True, text=True)


def pf_flush() -> None:
    subprocess.run(["pfctl", "-a", PF_ANCHOR, "-F", "all"], capture_output=True, text=True)


def pf_clear() -> None:
    pf_flush()
    if _pf_token:
        subprocess.run(["pfctl", "-X", _pf_token], capture_output=True, text=True)


def ensure_routes(st: dict, iface: str, all_vpn: bool = False) -> int:
    nets = [str(ipaddress.ip_network(n, strict=False)) for n in all_networks(st)]
    have = routes_on(iface)
    # also everything Amnezia itself routes into the tunnel (its DNS servers): with an empty Amnezia list
    # its AllowedIPs could be empty and DNS through the tunnel would be dropped
    own = tunnel_ip(iface)
    if not wg_allow(iface, nets + [n for n in have if n != f"{own}/32"]):
        return 0  # the tunnel does not take them: routing them in would only cut those sites off
    added = 0
    for net in nets:
        if net not in have:
            added += route_add(net, iface)
    pf_cut_direct(physical_iface(), iface, nets, all_vpn)
    return added


# ---------- probes ----------

def tcp_probe(ip: str, port: int, iface: str, sni: str | None = None) -> str:
    """'ok' | 'timeout' | 'reset' | 'unreachable' | 'error' — TCP connect (and TLS handshake if sni) pinned to iface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(PROBE_TIMEOUT)
    try:
        s.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, socket.if_nametoindex(iface))
        s.connect((ip, port))
        if sni is not None:  # "" = TLS handshake without a server name
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(s, server_hostname=sni or None) as t:
                t.do_handshake()
        return "ok"
    except socket.timeout:
        return "timeout"
    except ConnectionResetError:
        return "reset"
    except OSError as e:
        if e.errno in (51, 65):
            return "unreachable"
        return "reset" if e.errno in (54, 57) else "error"
    finally:
        s.close()


RU_TLDS = (".ru", ".su", ".xn--p1ai", ".xn--d1acj3b", ".moscow", ".xn--80adxhks")


def russian(host: str) -> bool:
    return host.rstrip(".").lower().endswith(RU_TLDS)


def skip(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return any(a in n for n in NEVER)


def covered(st: dict, ip: str) -> bool:
    """ip is in a base/group network or already belongs to a site: fast with thousands of sites."""
    if ip in st.get("_ips", ()):
        return True
    a = ipaddress.ip_address(ip)
    return any(a in n for n in st.get("_nets", ()))


def index_ips(st: dict) -> None:
    st["_ips"] = {ip for s in st["sites"].values() for ip in s["ips"]} if st.get("enabled", True) else set()
    st["_nets"] = [ipaddress.ip_network(n) for n in group_nets(st)]


# ---------- watcher ----------

NETTOP_CONN = re.compile(r"^tcp4 (\d+\.\d+\.\d+\.\d+):\d+<->(\d+\.\d+\.\d+\.\d+):(\d+),(\w+),(\d+),(\d+),")
NETTOP_PROC = re.compile(r"^(.+)\.(\d+),,")


def stalled(tun_ip: str | None) -> dict[tuple[str, int], tuple[str, str]]:
    """(ip, port) -> (kind, program). kind 'syn': stuck connecting; 'tls': HTTPS request sent, 0 bytes back."""
    out: dict[tuple[str, int], tuple[str, str]] = {}
    proc = ""
    for line in sh("nettop", "-m", "tcp", "-L", "1", "-n", "-J", "state,bytes_in,bytes_out").splitlines():
        m = NETTOP_CONN.match(line)
        if not m:
            pm = NETTOP_PROC.match(line)
            if pm:
                proc = pm.group(1)
            continue
        local, ip, port, state, b_in, b_out = m.group(1), m.group(2), int(m.group(3)), m.group(4), int(m.group(5)), int(m.group(6))
        if tun_ip and local == tun_ip:
            continue
        if state == "SynSent":
            out[(ip, port)] = ("syn", proc)
        elif state in ("Established", "FinWait1", "FinWait2", "CloseWait") and port == 443 and b_in == 0 and b_out > 0:
            # request sent, nothing back; FinWait — the program already gave up on it
            out[(ip, port)] = ("tls", proc)
    return out


class Service:
    """All changes of state and of the system (routes, pf, tunnel) happen in the main thread. Other threads only
    put commands into a queue (socket server) or read a snapshot (status writer)."""

    PROBES_PER_PASS = 3  # one pass must not hang for minutes on dozens of stalled connections

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.st = load()
        index_ips(self.st)
        self.sni = SniMap()
        self.sni_watch = SniWatcher(self._on_sni)
        self.tun: str | None = None
        self.first_seen: dict[tuple[str, int], float] = {}
        self.tested: dict[str, float] = {}
        self.pending_sni: list[tuple[str, str]] = []
        self.q: queue.Queue = queue.Queue(maxsize=200)
        self.all_vpn = False  # 0/1 + 128/1 routes are ours right now
        self.endpoint_route: str | None = None  # host route to the VPN server we added
        self._direct_ok: bool | None = None
        self._direct_checked = 0.0

    # -- threads that never touch the system --
    def _on_sni(self, ip: str, host: str) -> None:
        host = clean_host(host)
        if not host:
            return
        self.sni.put(ip, host)
        with self.lock:
            if len(self.pending_sni) < 1000:  # while the VPN is off nobody drains it
                self.pending_sni.append((ip, host))

    def socket_server(self) -> None:
        try:
            os.unlink(ipc.SOCK)
        except FileNotFoundError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(ipc.SOCK)
        os.chmod(ipc.SOCK, 0o666)  # anyone may connect; who is talking is checked per connection
        srv.listen(8)
        while True:
            conn, _ = srv.accept()
            try:
                conn.settimeout(2)
                uid = ipc.peer_uid(conn)
                if uid not in (0, ipc.console_uid()):
                    conn.sendall(b"denied\n")
                    continue
                data = b""
                while not data.endswith(b"\n") and len(data) < ipc.MAX_MSG:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                c = json.loads(data[:ipc.MAX_MSG] or b"{}")
                op = c.get("op") if isinstance(c, dict) else None
                site = c.get("site") if isinstance(c, dict) else ""
                if op not in ipc.OPS or not isinstance(site, str) or len(site) > 300:
                    conn.sendall(b"bad\n")
                    continue
                self.q.put_nowait((op, site))
                conn.sendall(b"ok\n")
            except (OSError, ValueError, queue.Full):
                pass
            finally:
                conn.close()

    def status_writer(self) -> None:
        while True:
            try:
                with self.lock:
                    snap = {"tunnel": self.tun, "updated": time.time(), "sites": len(self.st["sites"]),
                            "ips": len(self.st.get("_ips", ())), "enabled": self.st["enabled"],
                            "autostart": self.st["autostart"], "all_vpn": self.all_vpn,
                            "direct_ok": self._direct_ok}
                safe_write(STATUS, json.dumps(snap))
            except Exception as e:  # noqa: BLE001
                log(f"не записал статус: {e}")
            time.sleep(1)

    # -- main thread --
    def own_addresses(self) -> set[str]:
        """Addresses that must never be routed into the tunnel by a command or a guess: the VPN server, the
        tunnel itself, the gateway."""
        out = set()
        if self.tun:
            for a in (wg_endpoint(self.tun), tunnel_ip(self.tun)):
                if a:
                    out.add(a)
        gw = default_gw(physical_iface())
        if gw:
            out.add(gw)
        return out

    def add_ip(self, ip: str, host: str | None, app: str, reason: str) -> None:
        ip = valid_ip(ip)
        host = clean_host(host)
        if not ip or ip in self.own_addresses():
            return
        with self.lock:
            name = site_of(host) if host else f"?{ip}"
            if name in self.st["direct"] or (name not in self.st["sites"] and len(self.st["sites"]) >= MAX_SITES):
                return
            old = site_by_ip(self.st, ip)
            if old and old.startswith("?") and host:  # name an address learned earlier without one
                s = self.st["sites"].pop(old)
                s["ips"].remove(ip)
                if s["ips"]:
                    self.st["sites"][old] = s
            s = self.st["sites"].setdefault(name, {"ips": [], "hosts": [], "app": "", "added": now_s()})
            if ip not in s["ips"] and len(s["ips"]) < 256:
                s["ips"].append(ip)
            if host and host not in s["hosts"] and len(s["hosts"]) < 32:
                s["hosts"].append(host)
            if app and not s.get("app"):
                s["app"] = app[:64]
            s["last"] = now_s()
            save(self.st)
        if self.tun and wg_allow(self.tun, [f"{ip}/32"]):
            route_add(f"{ip}/32", self.tun)
            self.refresh_pf()
        log(f"+ {name}  {ip}  ({app or '?'}; {reason})")

    def remove_site(self, name: str, keep_direct: bool) -> None:
        with self.lock:
            s = self.st["sites"].pop(name, None)
            if keep_direct and not name.startswith("?") and name not in self.st["direct"]:
                self.st["direct"].append(name)
            save(self.st)
        for ip in (s or {}).get("ips", []):
            route_delete_host(ip)
            self.tested[ip] = time.time()
        self.refresh_pf()
        log(f"- {name} убран из VPN" + (" и всегда напрямую" if keep_direct else ""))

    def handle(self, op: str, raw_site: str) -> None:
        if op in ("enable", "disable"):
            self.set_enabled(op == "enable")
        elif op in ("autostart_on", "autostart_off"):
            with self.lock:
                self.st["autostart"] = op == "autostart_on"
                save(self.st)
            log("автозагрузка " + ("включена" if self.st["autostart"] else "выключена"))
        elif op in ("group_on", "group_off"):
            pass  # YouTube is built in since 0.3.2
        elif op in ("remove", "direct"):
            name = raw_site.strip().lower()
            if name in self.st["sites"]:
                self.remove_site(name, keep_direct=op == "direct")
        elif op == "undirect":
            name = clean_host(raw_site)
            with self.lock:
                if name and name in self.st["direct"]:
                    self.st["direct"].remove(name)
                    save(self.st)
                    log(f"{name}: снова может идти через VPN")
        elif op == "add":
            ip = valid_ip(raw_site.strip())
            if ip:
                self.add_ip(ip, None, "вручную", "добавлен вручную")
                return
            host = clean_host(raw_site)
            if not host:
                log("не похоже на адрес сайта — не добавляю")
                return
            with self.lock:
                if site_of(host) in self.st["direct"]:
                    self.st["direct"].remove(site_of(host))
            try:
                ips = sorted({a[4][0] for a in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)})
            except OSError:
                log(f"{host}: не нашёл адрес")
                return
            for ip in ips[:16]:
                self.add_ip(ip, host, "вручную", "добавлен вручную")

    def drain(self, wait: float) -> None:
        """Run queued commands; wait up to `wait` seconds for the first one (replaces sleep in the loop)."""
        deadline = time.time() + wait
        while True:
            try:
                op, site = self.q.get(timeout=max(0.0, deadline - time.time()))
            except queue.Empty:
                return
            try:
                self.handle(op, site)
            except Exception as e:  # noqa: BLE001
                log(f"ошибка команды {op}: {e}")

    def set_enabled(self, on: bool) -> None:
        with self.lock:
            if self.st["enabled"] == on:
                return
            self.st["enabled"] = on
            save(self.st)
            ips = [ip for s in self.st["sites"].values() for ip in s["ips"]]
        if on:
            if self.tun:
                self.all_through_vpn(False)
                ensure_routes(self.st, self.tun)
            log("включено: через VPN только Telegram, Claude, YouTube и найденные сайты")
        else:
            self.drop_extra_routes(ips)
            if self.tun:
                self.all_through_vpn(True)
            self.refresh_pf()
            log("выключено: весь трафик через VPN, как обычно")

    def all_through_vpn(self, on: bool) -> None:
        """Off = a plain VPN: everything goes through the tunnel (0/1 + 128/1, AllowedIPs 0.0.0.0/0), the VPN
        server itself stays on the direct route so the tunnel does not loop into itself."""
        tun = self.tun
        if not tun:
            return
        if on:
            if not wg_allow(tun, ["0.0.0.0/0"]):
                return
            endpoint = wg_endpoint(tun)
            gw = default_gw(physical_iface())
            if endpoint and gw and valid_ip(endpoint):
                subprocess.run(["route", "-n", "add", "-host", endpoint, gw], capture_output=True, text=True)
                self.endpoint_route = endpoint
            for net in ("0.0.0.0/1", "128.0.0.0/1"):
                route_add(net, tun)
            self.all_vpn = True
        else:
            for net in ("0.0.0.0/1", "128.0.0.0/1"):
                subprocess.run(["route", "-n", "delete", "-net", net, "-interface", tun], capture_output=True, text=True)
            if self.endpoint_route:
                subprocess.run(["route", "-n", "delete", "-host", self.endpoint_route], capture_output=True, text=True)
                self.endpoint_route = None
            self.all_vpn = False
        self.refresh_pf()

    def drop_extra_routes(self, ips: list[str] | None = None) -> None:
        if ips is None:
            ips = [ip for s in self.st["sites"].values() for ip in s["ips"]]
        for ip in ips:
            route_delete_host(ip)
        for name, fn in GROUPS.items():
            for n in self.st.get("_group_cache", {}).get(name) or fn():
                subprocess.run(["route", "-n", "delete", "-net", n], capture_output=True, text=True)

    def refresh_pf(self) -> None:
        if self.tun:
            pf_cut_direct(physical_iface(), self.tun, all_networks(self.st), self.all_vpn)
        else:
            pf_flush()

    def set_group(self, name: str, on: bool) -> None:
        nets = GROUPS[name]()
        with self.lock:
            self.st["groups"][name] = on
            self.st.get("_group_cache", {}).pop(name, None)
            save(self.st)
        if on:
            if self.tun:
                ensure_routes(self.st, self.tun, self.all_vpn)
        else:
            for n in nets:
                subprocess.run(["route", "-n", "delete", "-net", n], capture_output=True, text=True)
            self.refresh_pf()
        log(f"{name}: " + ("всегда через VPN" if on else "по обычным правилам"))

    def cleanup(self) -> None:
        """On stop (launchctl bootout = SIGTERM, uninstall): take our pf rule and our 0/1 routes away, so the
        internet keeps working without the service. Routes into the tunnel vanish with it."""
        try:
            self.sni_watch.stop()
            if self.all_vpn:
                self.all_through_vpn(False)
            pf_clear()
            log("остановлен: фильтр снят")
        except Exception:  # noqa: BLE001
            pass

    def prune(self, now: float) -> None:
        if len(self.tested) > 20000:
            self.tested = {k: v for k, v in self.tested.items() if now - v < RETEST_AFTER}
        self.sni.prune()

    def run(self) -> None:
        ensure_root_data()
        import_old_state(os.environ.get("VPN_AUTOROUTE_DATA"))
        with self.lock:
            self.st = load()
            index_ips(self.st)
        threading.Thread(target=self.socket_server, daemon=True).start()
        threading.Thread(target=self.status_writer, daemon=True).start()
        if not self.st["autostart"] and self.st["enabled"]:
            self.st["enabled"] = False
            save(self.st)
        log(f"старт 0.3; базовые сети: {', '.join(BASE)}; сайтов в памяти: {len(self.st['sites'])}; "
            + ("включено" if self.st["enabled"] else "выключено"))
        for name in [n for n in self.st["sites"] if russian(n)]:
            self.remove_site(name, keep_direct=False)
        if self.st.get("schema", 1) < 3:
            for name in [n for n in self.st["sites"] if n.startswith("?")]:
                self.remove_site(name, keep_direct=False)
            self.st["schema"] = 3
            save(self.st)
        if not self.st["enabled"]:
            self.drop_extra_routes()
        last_ensure = 0.0
        while True:
            try:
                last_ensure = self.step(last_ensure)
            except Exception as e:  # noqa: BLE001 — one bad pass must not kill the service
                log(f"ошибка в цикле: {e!r}")
                self.drain(POLL)

    def step(self, last_ensure: float) -> float:
        tun = tunnel_iface()
        if tun != self.tun:
            log(f"туннель: {tun or 'нет (VPN выключен или это не AmneziaWG)'}")
            self.tun, last_ensure = tun, 0.0
            self._direct_ok, self._direct_checked = None, 0.0
            self.all_vpn, self.endpoint_route = False, None  # the old tunnel took its routes with it
            if not tun:
                pf_flush()
        phys = physical_iface()
        self.sni_watch.ensure(phys)
        now = time.time()
        self.prune(now)
        if not tun:
            with self.lock:
                self.pending_sni.clear()
            self.drain(POLL)
            return last_ensure
        enabled = self.st["enabled"]
        if now - last_ensure > 10:
            ensure_scoped_default(tun)
            ensure_direct_scoped_default(phys)
            if not enabled:
                if route_iface("1.1.1.1") != tun:  # VPN reconnected while switched off
                    self.all_through_vpn(True)
            else:
                n = ensure_routes(self.st, tun, self.all_vpn)
                if n:
                    log(f"восстановлено маршрутов в {tun}: {n}")
            last_ensure = now

        with self.lock:
            pend, self.pending_sni = self.pending_sni, []
        if enabled:
            for ip, host in pend:
                if valid_ip(ip) and not covered(self.st, ip) and site_of(host) in self.st["sites"]:
                    self.add_ip(ip, host, "", "новый адрес известного сайта")
        else:
            self.drain(POLL)
            return last_ensure

        if now - self._direct_checked > 30:
            # if even ya.ru does not open directly, the direct path itself is broken (network, captive portal,
            # a VPN filter): every site would look blocked — learn nothing, send everything through the VPN
            self._direct_checked = now
            ok = tcp_probe("77.88.55.242", 443, phys, "ya.ru") == "ok"
            if ok != self._direct_ok:
                if ok:
                    if self.all_vpn:
                        self.all_through_vpn(False)
                    if self._direct_ok is False:
                        log("прямой интернет снова работает: через VPN снова только нужные сайты")
                else:
                    self.all_through_vpn(True)
                    log(f"напрямую не открывается даже ya.ru (через {phys}) — пока весь трафик через VPN, "
                        "новые сайты не ищу")
            self._direct_ok = ok
        if self._direct_ok is False:
            self.drain(POLL)
            return last_ensure

        current = stalled(tunnel_ip(tun))
        for key in list(self.first_seen):
            if key not in current:
                del self.first_seen[key]
        probes = 0
        for (ip, port), (kind, app) in current.items():
            if probes >= self.PROBES_PER_PASS:
                break
            if not valid_ip(ip) or covered(self.st, ip):
                continue
            self.first_seen.setdefault((ip, port), now)
            if now - self.first_seen[(ip, port)] < STUCK or now - self.tested.get(ip, 0) < RETEST_AFTER:
                continue
            self.tested[ip] = now
            host = self.sni.get(ip)
            if host and (site_of(host) in self.st["direct"] or russian(host)):
                continue  # Russian sites are not blocked in Russia, and many refuse foreign (VPN) visitors
            if port == 443 and not host:
                continue  # no site name seen: system services (Apple push, maps), CDNs — guessing here did harm
            if not wg_allow(tun, [f"{ip}/32"]):  # let the probe through the tunnel; no route yet
                continue
            probes += 1
            if port == 443:
                d = tcp_probe(ip, port, phys, host or "")
                v = tcp_probe(ip, port, tun, host or "") if d in ("timeout", "reset") else "-"
            else:
                d = tcp_probe(ip, port, phys)
                v = tcp_probe(ip, port, tun) if d in ("timeout", "reset") else "-"
            if v == "ok":
                self.add_ip(ip, host, app, f"напрямую: {d}, через VPN: ok")
            elif v != "-":
                self.tested[ip] = now - RETEST_AFTER + RETRY_FAILED
                log(f"  {host or ip} {ip}:{port} ({app}) завис, через VPN тоже нет ({v}) — повторю через {RETRY_FAILED} с")
            self.drain(0)  # answer the window between probes
        self.drain(POLL)
        return last_ensure


# ---------- CLI ----------

def send(op: str, site: str) -> None:
    print("передано службе" if ipc.send(op, site) else "служба не отвечает")


def cmd_list() -> None:
    st = load()
    for g, nets in BASE.items():
        print(f"[{g}] {len(nets)} сетей")
    for name, s in sorted(st["sites"].items()):
        print(f"{name:28} {', '.join(s['ips'])}  {s.get('app', '')}  {s.get('added', '')}")
    if st["direct"]:
        print("всегда напрямую:", ", ".join(st["direct"]))


def cmd_check() -> None:
    tun, phys = tunnel_iface(), physical_iface()
    print(f"туннель VPN: {tun}   прямой интерфейс: {phys}")
    print(f"маршрут по умолчанию сейчас: {route_iface('1.1.1.1')} (если utun — VPN заворачивает весь трафик)")
    for g, nets in BASE.items():
        via = {route_iface(net_probe_ip(n)) for n in nets}
        print(f"  {g}: идёт через {', '.join(sorted(x or '?' for x in via))}")
    if not tun:
        return
    for host in ("telegram.org", "claude.ai", "ya.ru", "x.com"):
        ip = socket.gethostbyname(host)
        print(f"  {host:14} {ip:16} напрямую={tcp_probe(ip, 443, phys, host):12} через VPN={tcp_probe(ip, 443, tun, host)}")


def cmd_probe(target: str) -> None:
    """Root: allow the site's addresses in the tunnel and test each directly and through the VPN."""
    tun, phys = tunnel_iface(), physical_iface()
    if not tun:
        sys.exit("VPN не подключён")
    try:
        ips = [str(ipaddress.ip_address(target))]
        host = None
    except ValueError:
        ips = sorted({x[4][0] for x in socket.getaddrinfo(target, 443, socket.AF_INET, socket.SOCK_STREAM)})
        host = target
    if os.geteuid() == 0:
        wg_allow(tun, [f"{ip}/32" for ip in ips])
        ensure_scoped_default(tun)
    for ip in ips:
        print(f"{ip:16} напрямую={tcp_probe(ip, 443, phys, host):12} через VPN={tcp_probe(ip, 443, tun, host)}")


def main() -> None:
    a = sys.argv[1:]
    if a[:1] == ["run"]:
        if os.geteuid() != 0:
            sys.exit("Нужны права администратора: sudo python3 autoroute.py run")
        svc = Service()

        def stop(signum, _frame):  # launchctl bootout / uninstall send SIGTERM
            raise SystemExit(0)

        signal.signal(signal.SIGTERM, stop)
        try:
            svc.run()
        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            svc.cleanup()
    elif a[:1] == ["check"]:
        cmd_check()
    elif a[:1] == ["add"] and len(a) > 1:
        send("add", a[1])
    elif a[:1] == ["remove"] and len(a) > 1:
        send("remove", a[1])
    elif a[:1] == ["probe"] and len(a) > 1:
        cmd_probe(a[1])
    elif a[:1] == ["list"]:
        cmd_list()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
