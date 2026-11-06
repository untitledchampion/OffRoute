"""Read TLS ClientHello server names (SNI) from a tcpdump pcap stream: which site a connection to an IP was for."""

from __future__ import annotations

import struct
import subprocess
import threading
import time
from collections.abc import Callable

# start of a TLS handshake record, or a pushed segment (the tail of a two-segment ClientHello)
FILTER = "tcp dst port 443 and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16 or tcp[tcpflags] & tcp-push != 0)"


def parse_sni(data: bytes) -> str | None:
    """Server name from a TLS record that starts a ClientHello, or None."""
    try:
        if len(data) < 6 or data[0] != 0x16 or data[5] != 0x01:
            return None
        p = 5 + 4 + 2 + 32  # handshake header, client version, random
        p += 1 + data[p]  # session id
        p += 2 + struct.unpack_from("!H", data, p)[0]  # cipher suites
        p += 1 + data[p]  # compression methods
        end = p + 2 + struct.unpack_from("!H", data, p)[0]
        p += 2
        while p + 4 <= end:
            etype, elen = struct.unpack_from("!HH", data, p)
            p += 4
            if etype == 0:  # server_name
                q = p + 2
                while q + 3 <= p + elen:
                    ntype, nlen = data[q], struct.unpack_from("!H", data, q + 1)[0]
                    if ntype == 0:
                        return data[q + 3:q + 3 + nlen].decode("ascii", "replace").lower()
                    q += 3 + nlen
                return None
            p += elen
    except (IndexError, struct.error):
        return None
    return None


def _packets(stream):
    """Yield (dst_ip, payload) from a pcap byte stream (Ethernet or BSD loopback/null link)."""
    head = stream.read(24)
    if len(head) < 24:
        return
    endian = "<" if head[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    linktype = struct.unpack(endian + "I", head[20:24])[0]
    while True:
        rec = stream.read(16)
        if len(rec) < 16:
            return
        incl = struct.unpack(endian + "IIII", rec)[2]
        pkt = stream.read(incl)
        if linktype == 1:  # Ethernet
            if len(pkt) < 14 or pkt[12:14] != b"\x08\x00":
                continue
            ip = pkt[14:]
        elif linktype == 0:  # BSD null
            ip = pkt[4:]
        else:
            continue
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 0x0F) * 4
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue
        payload = tcp[(tcp[12] >> 4) * 4:]
        sport = struct.unpack("!H", tcp[0:2])[0]
        yield ".".join(str(b) for b in ip[16:20]), sport, payload


class SniWatcher:
    """Runs tcpdump on the direct interface and calls on_sni(ip, name) for each ClientHello seen."""

    def __init__(self, on_sni: Callable[[str, str], None]):
        self.on_sni = on_sni
        self.iface: str | None = None
        self.proc: subprocess.Popen | None = None

    def ensure(self, iface: str) -> None:
        if self.iface == iface and self.proc and self.proc.poll() is None:
            return
        self.stop()
        self.iface = iface
        self.proc = subprocess.Popen(
            ["tcpdump", "-U", "-n", "-i", iface, "-s", "2048", "-w", "-", FILTER],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        threading.Thread(target=self._read, args=(self.proc,), daemon=True).start()

    def _read(self, proc: subprocess.Popen) -> None:
        # A ClientHello with a post-quantum key share is ~1.5-2 KB and spans two TCP segments;
        # browsers shuffle extensions, so the server name may be in the second one.
        partial: dict[tuple[str, int], bytes] = {}
        for ip, sport, payload in _packets(proc.stdout):
            key = (ip, sport)
            if key in partial:
                data = partial.pop(key) + payload
            elif payload[:1] == b"\x16":
                data = payload
            else:
                continue
            need = 5 + struct.unpack_from("!H", data, 3)[0] if len(data) >= 5 else 1 << 30
            name = parse_sni(data)
            if name:
                self.on_sni(ip, name)
            elif len(data) < need and len(partial) < 1000:
                partial[key] = data

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None


class SniMap:
    """ip -> (name, time) for recent ClientHellos."""

    def __init__(self, ttl: float = 600):
        self.ttl = ttl
        self._m: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    MAX = 20000

    def put(self, ip: str, name: str) -> None:
        with self._lock:
            if len(self._m) >= self.MAX:
                self._prune_locked()
                if len(self._m) >= self.MAX:
                    self._m.clear()
            self._m[ip] = (name, time.time())

    def _prune_locked(self) -> None:
        now = time.time()
        self._m = {k: v for k, v in self._m.items() if now - v[1] < self.ttl}

    def prune(self) -> None:
        with self._lock:
            if len(self._m) > 1000:
                self._prune_locked()

    def get(self, ip: str) -> str | None:
        with self._lock:
            v = self._m.get(ip)
            if v and time.time() - v[1] < self.ttl:
                return v[0]
            return None
