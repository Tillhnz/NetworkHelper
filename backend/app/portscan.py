"""Offene Ports von außen.

Zwei Blickwinkel:
1. Eigener Scan: NetworkHelper verbindet sich mit der öffentlichen IP (und weiteren Zielen) auf einer Liste häufiger
   Ports. Weil der Scan aus dem Heimnetz kommt, beantwortet der Router ihn über „NAT-Loopback“. Das zeigt zuverlässig
   die eingerichteten Portweiterleitungen, kann aber Ports des Routers selbst enthalten, die von außen zu sind.
2. Shodan InternetDB: was der Suchdienst Shodan zuletzt von außen gesehen hat (kostenlos, ohne Schlüssel,
   wöchentlich aktualisiert). Nur die öffentliche IP wird dorthin gesendet.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from datetime import datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import notify, publicip, state
from .config import settings
from .models import ExpectedPort, PortFinding
from .server_settings import parse_ports

log = logging.getLogger("networkhelper.scan")

SERVICES = {
    20: "FTP-Daten", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 81: "Proxy Manager (Verwaltung)",
    88: "Kerberos", 110: "POP3", 111: "RPC", 135: "Windows RPC", 137: "NetBIOS", 139: "NetBIOS/SMB", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB (Windows-Freigaben)", 465: "SMTPS", 500: "IPsec", 548: "AFP",
    554: "RTSP (Kamera)", 587: "SMTP Submission", 631: "Drucker (IPP)", 636: "LDAPS", 853: "DNS over TLS", 873: "rsync",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS-Proxy", 1194: "OpenVPN", 1433: "MS SQL", 1521: "Oracle", 1723: "PPTP",
    1883: "MQTT", 1900: "UPnP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel", 2222: "SSH (alternativ)", 2375: "Docker-API (ungeschützt)",
    2376: "Docker-API (TLS)", 3000: "Web-App (3000)", 3001: "Web-App (3001)", 3128: "HTTP-Proxy", 3306: "MySQL/MariaDB", 3389: "Remote Desktop",
    4443: "HTTPS (alternativ)", 5000: "Synology/Web-App", 5001: "Synology HTTPS", 5060: "SIP", 5222: "XMPP", 5353: "mDNS",
    5432: "PostgreSQL", 5555: "Android Debug", 5672: "RabbitMQ", 5900: "VNC", 5901: "VNC", 6379: "Redis", 6443: "Kubernetes-API",
    7547: "TR-069 (Router-Fernwartung)", 8000: "Web-App (8000)", 8006: "Proxmox VE", 8007: "Proxmox Backup", 8008: "HTTP (alternativ)",
    8080: "HTTP (alternativ)", 8081: "HTTP (alternativ)", 8083: "Web-App", 8086: "InfluxDB", 8088: "Web-App", 8096: "Jellyfin",
    8123: "Home Assistant", 8181: "Web-App", 8200: "Vault", 8443: "HTTPS (alternativ)", 8448: "Matrix", 8501: "Web-App",
    8888: "Web-App (8888)", 8920: "Jellyfin HTTPS", 9000: "Portainer/Web-App", 9090: "Cockpit/Prometheus", 9091: "Transmission",
    9100: "Drucker/Node-Exporter", 9200: "Elasticsearch", 9443: "Portainer HTTPS", 10000: "Webmin", 11211: "Memcached",
    25565: "Minecraft", 27017: "MongoDB", 32400: "Plex", 51820: "WireGuard (UDP)", 51413: "BitTorrent",
}
# Dienste, die man fast nie direkt ins Internet stellen sollte
RISKY = {21, 22, 23, 81, 111, 135, 137, 139, 445, 1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5555, 5900, 5901, 6379,
         6443, 7547, 8006, 8007, 9000, 9090, 9200, 10000, 11211, 27017}
DEFAULT_PORTS = sorted(p for p in SERVICES if p not in (51820, 5353, 1900, 137, 500))


def ports_to_scan() -> list[int]:
    if settings.scan_ports.strip():
        try:
            return parse_ports(settings.scan_ports)
        except ValueError:
            pass
    return DEFAULT_PORTS


def expected(db: Session) -> set[int]:
    rows = {p.port for p in db.scalars(select(ExpectedPort))}
    if not rows:
        try:
            rows = set(parse_ports(settings.expected_ports))
        except ValueError:
            rows = {80, 443}
    return rows


async def _probe(host: str, port: int, sem: asyncio.Semaphore, timeout: float) -> tuple[int, str | None] | None:
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        except (OSError, asyncio.TimeoutError):
            return None
        banner = None
        if port not in (80, 443, 8080, 8443, 4443):
            try:
                data = await asyncio.wait_for(reader.read(80), 1.2)
                text = data.decode("latin-1", "replace").strip().splitlines()
                banner = text[0][:120] if text else None
            except (OSError, asyncio.TimeoutError):
                pass
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except (OSError, asyncio.TimeoutError):
            pass
        return port, banner


async def scan_host(host: str, ports: list[int], timeout: float = 1.5, concurrency: int = 150) -> dict[int, str | None]:
    sem = asyncio.Semaphore(concurrency)
    results = await asyncio.gather(*(_probe(host, p, sem, timeout) for p in ports))
    return {r[0]: r[1] for r in results if r}


def shodan_lookup(ip: str) -> dict | None:
    """Daten von internetdb.shodan.io. None, wenn Shodan nichts weiß oder nicht erreichbar ist."""
    try:
        r = httpx.get(f"https://internetdb.shodan.io/{ip}", timeout=15)
    except httpx.HTTPError:
        return None
    if r.status_code == 404:
        return {"ports": [], "vulns": [], "hostnames": [], "cpes": [], "tags": [], "unknown": True}
    if r.status_code != 200:
        return None
    return r.json()


def _record(db: Session, target: str, source: str, found: dict[int, str | None], now: datetime) -> list[PortFinding]:
    """Speichert Treffer; gibt neu (oder wieder) geöffnete Ports zurück."""
    rows = {(f.port): f for f in db.scalars(select(PortFinding).where(PortFinding.target == target, PortFinding.source == source))}
    fresh = []
    for port, banner in found.items():
        f = rows.get(port)
        if f is None:
            f = PortFinding(target=target, port=port, source=source, first_seen=now)
            db.add(f)
            fresh.append(f)
        elif not f.open:
            fresh.append(f)
        f.open, f.closed_at, f.last_seen = True, None, now
        f.service = SERVICES.get(port)
        if banner:
            f.banner = banner
    for port, f in rows.items():
        if port not in found and f.open:
            f.open, f.closed_at = False, now
    return fresh


def run(db: Session) -> dict:
    """Ein kompletter Durchlauf. Ergebnis wird auch unter state 'portscan_last' gespeichert."""
    started = datetime.utcnow()
    ip = publicip.current(db, refresh=True)
    targets = []
    if ip:
        targets.append(ip)
    for t in [x.strip() for x in settings.scan_targets.split(",") if x.strip()]:
        if t not in targets:
            targets.append(t)
    ports = ports_to_scan()
    summary = {"started": started.isoformat(), "targets": targets, "ports": len(ports), "open": {}, "errors": [], "shodan": None}
    if not targets:
        summary["errors"].append("Keine öffentliche IP gefunden und keine Ziele eingetragen.")
    new_findings: list[PortFinding] = []
    for t in targets:
        try:
            socket.getaddrinfo(t, None)
        except OSError:
            summary["errors"].append(f"{t}: Name lässt sich nicht auflösen")
            continue
        try:
            found = asyncio.run(scan_host(t, ports))
        except Exception as e:  # noqa: BLE001
            summary["errors"].append(f"{t}: {e}")
            continue
        summary["open"][t] = sorted(found)
        new_findings += _record(db, t, "scan", found, started)
    if ip and settings.shodan_enabled:
        sh = shodan_lookup(ip)
        if sh is not None:
            summary["shodan"] = {k: sh.get(k, []) for k in ("ports", "vulns", "hostnames", "cpes", "tags")}
            summary["shodan"]["unknown"] = bool(sh.get("unknown"))
            new_findings += _record(db, ip, "shodan", {p: None for p in sh.get("ports", [])}, started)
            vulns = sh.get("vulns") or []
            if vulns:
                notify.raise_alert(db, "warn", "ports", f"Shodan meldet {len(vulns)} bekannte Schwachstelle(n) für {ip}",
                                   "Betroffene Kennungen: " + ", ".join(vulns[:20]) + "\nDetails: https://internetdb.shodan.io/" + ip,
                                   dedupe_key=f"shodan-vulns:{ip}:{','.join(sorted(vulns))}", dedupe_hours=24 * 7)
    db.commit()
    ok_ports = expected(db)
    for f in new_findings:
        if f.port in ok_ports:
            continue
        sev = "crit" if f.port in RISKY else "warn"
        where = "laut Shodan von außen sichtbar" if f.source == "shodan" else "über die öffentliche Adresse erreichbar"
        notify.raise_alert(db, sev, "ports", f"Port {f.port} ({f.service or 'unbekannt'}) ist offen auf {f.target}",
                           f"Der Port ist {where}.\nFalls das gewollt ist, markiere ihn unter Sicherheit → Ports als erwartet."
                           + (f"\nAntwort des Dienstes: {f.banner}" if f.banner else ""),
                           dedupe_key=f"port:{f.target}:{f.port}:{f.source}", dedupe_hours=24)
    summary["finished"] = datetime.utcnow().isoformat()
    summary["new"] = [{"target": f.target, "port": f.port, "source": f.source} for f in new_findings]
    state.put(db, "portscan_last", summary)
    return summary
