"""Zugriffsprotokolle des Nginx Proxy Managers einlesen.

Der Agent schickt die Zeilen unverändert. Ausgewertet wird hier, damit ein neues Format nur ein Update von
NetworkHelper braucht und nicht von jedem Agenten.

Format der Proxy Hosts (nginx.conf im Proxy Manager, log_format proxy):
  [24/Oct/2026:13:55:36 +0200] - 200 200 - GET https cloud.example.de "/index.php" [Client 203.0.113.7]
  [Length 512] [Gzip -] [Sent-to 192.168.1.20] "Mozilla/5.0 …" "-"
Daneben wird das übliche „combined“-Format verstanden (Default Host, andere Webserver).
"""
from __future__ import annotations

import ipaddress
import re
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import geoip
from .models import AccessEvent, BlockEntry

def _q(name: str) -> str:
    """Ein Feld in Anführungszeichen, maskierte Anführungszeichen erlaubt."""
    return rf'"(?P<{name}>(?:[^"\\]|\\.)*)"'


PROXY_RE = re.compile(
    r"^\[(?P<time>[^\]]+)\]\s+(?:\S+\s+)*?(?P<status>\d{3})\s+-\s+(?P<method>[A-Z]+|-)\s+(?P<scheme>\S+)\s+(?P<host>\S+)\s+"
    + _q("path")
    + r"\s+\[Client\s+(?P<ip>[^\]]+)\]\s+\[Length\s+(?P<len>[^\]]*)\]\s+\[Gzip\s+[^\]]*\]"
    + r"(?:\s+\[Sent-to\s+(?P<upstream>[^\]]*)\])?\s+"
    + _q("ua") + r"\s+" + _q("ref")
)
COMBINED_RE = re.compile(
    r"^(?:\[(?P<host>[^\]]+)\]\s+)?(?P<ip>[0-9a-fA-F:.]+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"
    + r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})\s+(?P<len>\d+|-)'
    + r"(?:\s+" + _q("ref") + r"\s+" + _q("ua") + r")?"
)
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
TIME_RE = re.compile(r"(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?")


def parse_time(text: str) -> datetime | None:
    """'24/Oct/2026:13:55:36 +0200' -> UTC ohne Zeitzone."""
    m = TIME_RE.search(text)
    if not m or m.group(2) not in MONTHS:
        return None
    d, mon, y, hh, mm, ss, off = m.groups()
    tz = timezone.utc
    if off:
        sign = 1 if off[0] == "+" else -1
        tz = timezone(sign * timedelta(hours=int(off[1:3]), minutes=int(off[3:5])))
    try:
        dt = datetime(int(y), MONTHS[mon], int(d), int(hh), int(mm), int(ss), tzinfo=tz)
    except ValueError:
        return None
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def _clean(v: str | None, n: int) -> str | None:
    if v is None or v in ("-", ""):
        return None
    return v.replace('\\"', '"')[:n]


def parse_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    m = PROXY_RE.match(line) or COMBINED_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    ts = parse_time(g["time"])
    ip = (g.get("ip") or "").strip()
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return None
    if ts is None:
        return None
    length = g.get("len")
    return {
        "ts": ts,
        "host": (g.get("host") or "-").lower()[:253],
        "method": (g.get("method") or "-")[:12],
        "scheme": (g.get("scheme") or None) and g["scheme"][:8],
        "path": (g.get("path") or "/").replace('\\"', '"')[:1000],
        "status": int(g["status"]),
        "bytes": int(length) if length and length.isdigit() else None,
        "ip": ip,
        "user_agent": _clean(g.get("ua"), 400),
        "referer": _clean(g.get("ref"), 400),
        "upstream": _clean(g.get("upstream"), 120),
    }


class _BlockCache:
    """Aktive Sperren für die Markierung „abgewiesen“, alle 30 Sekunden neu gelesen."""

    def __init__(self):
        self.nets: list = []
        self.loaded = 0.0
        self.lock = threading.Lock()

    def get(self, db: Session) -> list:
        with self.lock:
            if time.monotonic() - self.loaded > 30:
                now = datetime.utcnow()
                rows = db.scalars(select(BlockEntry.cidr).where((BlockEntry.expires_at.is_(None)) | (BlockEntry.expires_at > now))).all()
                self.nets = [ipaddress.ip_network(c, strict=False) for c in rows]
                self.loaded = time.monotonic()
            return self.nets

    def invalidate(self) -> None:
        with self.lock:
            self.loaded = 0.0


block_cache = _BlockCache()


def ingest(db: Session, lines: list[str], agent_id: int | None = None) -> tuple[int, int]:
    """Wertet Zeilen aus und speichert sie. Gibt (gespeichert, nicht lesbar) zurück."""
    from . import publicip
    nets = block_cache.get(db)
    periods = publicip.own_periods(db)
    ok = bad = 0
    rows = []
    for line in lines:
        ev = parse_line(line)
        if ev is None:
            if line.strip():
                bad += 1
            continue
        if publicip.is_own(periods, ev["ip"], ev["ts"]):
            country, asn, org = None, None, "Heimnetz"  # du selbst von zu Hause über deine Domain
        else:
            country, asn, org = geoip.lookup(ev["ip"])
        blocked = None
        if nets and ev["status"] == 403:
            addr = ipaddress.ip_address(ev["ip"])
            blocked = any(addr in n for n in nets) or None
        if ev.get("status") == 444:
            blocked = True  # vom Proxy Manager ohne Antwort abgewiesen (Länder- oder Listen-Sperre)
        rows.append(AccessEvent(agent_id=agent_id, country=country, asn=asn, as_org=org, blocked=blocked, **ev))
        ok += 1
    if rows:
        db.add_all(rows)
        db.commit()
    return ok, bad
