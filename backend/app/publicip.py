"""Öffentliche IPv4-Adresse des Anschlusses ermitteln."""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta

import httpx
from sqlalchemy.orm import Session

from . import notify, porkbun, state
from .config import settings

log = logging.getLogger("networkhelper.ip")
SOURCES = ["https://api.ipify.org", "https://ipv4.icanhazip.com", "https://v4.ident.me"]


def _valid(ip: str | None) -> str | None:
    try:
        addr = ipaddress.IPv4Address((ip or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.is_global else None


def detect() -> tuple[str | None, str]:
    """(IP, Quelle). Reihenfolge: feste Einstellung, Porkbun, öffentliche Dienste."""
    if settings.public_ip_override:
        return settings.public_ip_override, "Einstellung"
    if porkbun.configured():
        try:
            ip = _valid(porkbun.ping())
            if ip:
                return ip, "Porkbun"
        except porkbun.PorkbunError as e:
            log.info("Porkbun-Ping fehlgeschlagen: %s", e)
    for url in SOURCES:
        try:
            ip = _valid(httpx.get(url, timeout=8).text)
            if ip:
                return ip, url.split("//")[1]
        except httpx.HTTPError:
            continue
    return None, ""


def current(db: Session, max_age: timedelta = timedelta(minutes=5), refresh: bool = False) -> str | None:
    """Gemerkte IP; nach max_age wird neu ermittelt. Meldet Änderungen."""
    info, at = state.get_with_time(db, "public_ip")
    if not refresh and info and at and datetime.utcnow() - at < max_age:
        return info.get("ip")
    ip, source = detect()
    if not ip:
        return (info or {}).get("ip")
    old = (info or {}).get("ip")
    state.put(db, "public_ip", {"ip": ip, "source": source, "since": (info or {}).get("since") if old == ip else datetime.utcnow().isoformat()})
    if old and old != ip:
        notify.raise_alert(db, "info", "ip", f"Neue öffentliche IP: {ip}", f"Vorher: {old}", dedupe_key=f"ip:{ip}", dedupe_hours=1)
        try:  # neue Adresse gleich prüfen, Treffer der alten fallen dabei weg
            from . import scheduler
            if settings.scan_enabled and settings.background_jobs:
                scheduler.trigger("portscan")
        except Exception:  # noqa: BLE001
            pass
    return ip


def info(db: Session) -> dict:
    data, at = state.get_with_time(db, "public_ip")
    return {**(data or {}), "checked_at": at.isoformat() if at else None}
