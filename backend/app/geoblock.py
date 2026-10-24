"""Länder sperren und öffentliche Sperrlisten.

Umsetzung im Nginx Proxy Manager über den Agenten (nur wenn dort „Sperrliste umsetzen“ an ist):
- Im http-Block (custom/http_top.conf) steht eine geo-Tabelle Adressbereich → Land und eine geo-Tabelle der Sperrlisten.
  nginx durchsucht solche Tabellen als Baum, das kostet auch bei Hunderttausenden Einträgen kaum Zeit.
- Eine map entscheidet je Hostname und Land, ob gesperrt wird.
- In jedem Proxy Host (custom/server_proxy.conf) wird dann mit 444 (Verbindung ohne Antwort schließen) abgewiesen.
  Let's Encrypt (/.well-known/acme-challenge/) und das eigene Heimnetz bleiben immer erlaubt.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import re
import threading
from datetime import datetime, timedelta

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import geoip, publicip, state
from .config import settings
from .models import AccessEvent, GeoRule

log = logging.getLogger("networkhelper.geoblock")

FEEDS = {
    "spamhaus": {"name": "Spamhaus DROP", "urls": ["https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json"],
                 "about": "Netze, die vollständig Kriminellen gehören (gekapert oder für Spam und Angriffe vermietet). Sehr wenige Fehlalarme."},
    "firehol": {"name": "FireHOL Level 1", "urls": ["https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"],
                "about": "Zusammenfassung mehrerer Listen bekannter Angreifer. Etwas breiter, gilt aber noch als sicher für Webserver."},
}
LAN_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
            "::1/128", "fc00::/7", "fe80::/10"]
_PRIVATE = [ipaddress.ip_network(n) for n in LAN_NETS]
CIDR_RE = re.compile(r"(?<![\w:.])((?:\d{1,3}\.){3}\d{1,3}/\d{1,2}|[0-9a-fA-F:]+:[0-9a-fA-F:]*/\d{1,3})")
SERVER_SNIPPET = """# NetworkHelper: Länder- und Listen-Sperren
set $nh_deny 0;
if ($nh_feed_deny) { set $nh_deny 1; }
if ($nh_geo_deny) { set $nh_deny 1; }
if ($request_uri ~ "^/\\.well-known/acme-challenge/") { set $nh_deny 0; }
if ($nh_deny) { return 444; }
"""

_lock = threading.Lock()
_cache: dict = {"key": None, "text": None, "hash": None}
_cc_cache: dict = {"key": None, "nets": {}}


# ---------- Sperrlisten ----------

def clean_networks(cidrs, own_ip: str | None = None) -> list[str]:
    """Nur öffentliche Netze; nichts, was das Heimnetz oder die eigene Adresse träfe."""
    own = ipaddress.ip_address(own_ip) if own_ip else None
    out = []
    for c in cidrs:
        try:
            n = ipaddress.ip_network(c.strip(), strict=False)
        except ValueError:
            continue
        if n.is_private or n.is_reserved or n.is_multicast or n.is_loopback or n.is_link_local or n.is_unspecified:
            continue
        if n.prefixlen < (8 if n.version == 4 else 19):
            continue  # so große Bereiche sind in seriösen Listen nicht enthalten
        if any(n.version == p.version and n.overlaps(p) for p in _PRIVATE):
            continue
        if own is not None and own.version == n.version and own in n:
            continue
        out.append(n)
    return [str(n) for n in ipaddress.collapse_addresses([x for x in out if x.version == 4])] + \
        [str(n) for n in ipaddress.collapse_addresses([x for x in out if x.version == 6])]


def parse_feed(text: str) -> list[str]:
    nets = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        m = CIDR_RE.search(line.split(";")[0] if not line.startswith("{") else line)
        if m:
            nets.append(m.group(1))
        elif re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", line):
            nets.append(line + "/32")
    return nets


def enabled_feeds() -> list[str]:
    return [k for k in FEEDS if getattr(settings, f"feed_{k}", False)]


def refresh_feeds(db: Session) -> dict:
    """Lädt die eingeschalteten Listen (täglich). Bei Fehlern bleibt der letzte Stand."""
    result = {}
    for key in enabled_feeds():
        nets, errors = [], []
        for url in FEEDS[key]["urls"]:
            try:
                r = httpx.get(url, timeout=30, follow_redirects=True, headers={"User-Agent": "NetworkHelper/1.0"})
                r.raise_for_status()
                nets += parse_feed(r.text)
            except httpx.HTTPError as e:
                errors.append(f"{url}: {e.__class__.__name__}")
        if nets:
            state.put(db, f"feed:{key}", {"nets": nets, "fetched": datetime.utcnow().isoformat(), "errors": errors})
        result[key] = {"count": len(nets), "errors": errors}
    invalidate()
    return result


def feed_networks(db: Session) -> list[str]:
    raw = []
    for key in enabled_feeds():
        raw += (state.get(db, f"feed:{key}") or {}).get("nets", [])
    return clean_networks(raw, publicip.info(db).get("ip")) if raw else []


# ---------- Länder ----------

def country_networks(countries: set[str]) -> dict[str, list[str]]:
    """Alle Adressbereiche der genannten Länder aus der DB-IP-Länderdatenbank (zusammengefasst)."""
    reader = geoip._readers.get("country")
    if reader is None or not countries:
        return {}
    key = (os.path.getmtime(geoip._path("country")) if os.path.exists(geoip._path("country")) else 0, frozenset(countries))
    if _cc_cache["key"] == key:
        return _cc_cache["nets"]
    found: dict[str, list] = {c: [] for c in countries}
    for network, rec in reader:  # maxminddb >= 2.2: alle Netze durchgehen
        cc = ((rec or {}).get("country") or {}).get("iso_code")
        if cc in found:
            found[cc].append(network)
    nets = {}
    for cc, lst in found.items():
        v4 = ipaddress.collapse_addresses([n for n in lst if n.version == 4])
        v6 = ipaddress.collapse_addresses([n for n in lst if n.version == 6])
        nets[cc] = [str(n) for n in v4] + [str(n) for n in v6]
    _cc_cache.update(key=key, nets=nets)
    return nets


def parse_countries(text: str) -> list[str]:
    out = []
    for c in re.split(r"[\s,;]+", (text or "").upper()):
        if re.fullmatch(r"[A-Z]{2}", c) and c not in out:
            out.append(c)
    return out


def _host_re(host: str) -> str:
    return re.escape(host.lower()).replace("\\-", "-")


# ---------- Konfiguration für nginx ----------

def _inputs(db: Session):
    rules = db.scalars(select(GeoRule).where(GeoRule.enabled.is_(True)).order_by(GeoRule.host)).all()
    feeds = feed_networks(db)
    return rules, feeds


def invalidate() -> None:
    with _lock:
        _cache.update(key=None, text=None, hash=None)


def http_conf(db: Session) -> str:
    rules, feeds = _inputs(db)
    own_ip = publicip.info(db).get("ip")
    countries = set()
    for r in rules:
        countries.update(parse_countries(r.countries))
    key = (tuple((r.host, r.countries) for r in rules), hashlib.sha1("\n".join(feeds).encode()).hexdigest(), own_ip,
           os.path.getmtime(geoip._path("country")) if countries and os.path.exists(geoip._path("country")) else 0)
    with _lock:
        if _cache["key"] == key and _cache["text"] is not None:
            return _cache["text"]
    lines = [f"# Von NetworkHelper erzeugt am {datetime.utcnow():%Y-%m-%d %H:%M} UTC. Wird überschrieben.",
             "# Länderdaten: IP Geolocation by DB-IP (CC BY 4.0)", "", "geo $nh_feed_deny {", "    default 0;"]
    lines += [f"    {n} 1;" for n in feeds]
    lines += ["}", "", "geo $nh_cc {", "    default ZZ;"]
    lines += [f"    {n} LAN;" for n in LAN_NETS]
    if own_ip:
        lines.append(f"    {own_ip} LAN;")
    if countries:
        for cc, nets in sorted(country_networks(countries).items()):
            lines += [f"    {n} {cc};" for n in nets]
    lines += ["}", "", 'map "$host|$nh_cc" $nh_geo_deny {', "    default 0;"]
    wildcard = None
    for r in rules:
        allowed = parse_countries(r.countries)
        if not allowed:
            continue
        alt = "|".join(allowed + ["LAN"])
        if r.host == "*":
            wildcard = alt
            continue
        h = _host_re(r.host)
        lines += [f'    "~^{h}\\|({alt})$" 0;', f'    "~^{h}\\|" 1;']
    if wildcard:
        lines += [f'    "~\\|({wildcard})$" 0;', '    "~\\|" 1;']
    lines += ["}", ""]
    text = "\n".join(lines)
    with _lock:
        _cache.update(key=key, text=text, hash=hashlib.sha256(text.encode()).hexdigest()[:16])
    return text


def current(db: Session) -> tuple[str | None, str]:
    """(Hash der http-Konfiguration oder None, wenn nichts aktiv ist; Prüfung je Host)."""
    rules, feeds = _inputs(db)
    if not rules and not feeds:
        return None, ""
    http_conf(db)
    return _cache["hash"], SERVER_SNIPPET


# ---------- Vorschau ----------

def preview(db: Session, host: str, countries: list[str], days: int = 7) -> dict:
    """Was wäre in den letzten Tagen gesperrt worden? Inklusive Warnung, wenn eigene Nutzer betroffen wären."""
    from . import classify as cls
    E = AccessEvent
    since = datetime.utcnow() - timedelta(days=days)
    conds = [E.ts >= since, E.country.is_not(None), E.as_org.is_distinct_from("Heimnetz"), ~E.path.like("/.well-known/acme-challenge/%")]
    if host != "*":
        conds.append(E.host == host.lower())
    total = db.scalar(select(func.count()).where(*conds)) or 0
    blocked_conds = conds + ([E.country.not_in(countries)] if countries else [])
    rows = db.execute(select(E.country, func.count(), func.count(func.distinct(E.ip))).where(*blocked_conds)
                      .group_by(E.country).order_by(func.count().desc())).all()
    blocked = sum(r[1] for r in rows)
    top_ips = [ip for ip, in db.execute(select(E.ip).where(*blocked_conds).group_by(E.ip).order_by(func.count().desc()).limit(200))]
    affected_users = []
    if top_ips:
        for ip, c in cls.classify_ips(db, since, publicip.info(db).get("ip"), ips=top_ips).items():
            if c["group"] == "friendly" or c["category"] in ("acme", "monitor"):
                affected_users.append({"ip": ip, "label": c["label"], "who": c.get("who"), "country": c["stats"].get("country"),
                                       "count": c["stats"]["count"]})
    affected_users.sort(key=lambda a: -a["count"])
    return {"days": days, "total": total, "blocked": blocked, "share": round(blocked / total, 3) if total else 0,
            "countries": [{"country": c, "count": n, "ips": i} for c, n, i in rows[:15]], "affected_users": affected_users[:10]}
