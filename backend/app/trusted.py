"""„Das war ich“: Adressen, die für eine Weile nie gesperrt werden (z. B. das eigene Handy im Mobilfunk).

Mobilfunk-Adressen wechseln oft und werden von vielen Kunden geteilt, darum nur befristet.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from . import state

KEY = "trusted_ips"
HOURS = 24


def active(db: Session) -> dict[str, str]:
    now = datetime.utcnow()
    items = state.get(db, KEY) or {}
    return {ip: until for ip, until in items.items() if _parse(until) > now}


def _parse(text: str) -> datetime:
    try:
        return datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return datetime.min


def add(db: Session, ip: str, hours: float = HOURS) -> str:
    items = active(db)
    until = (datetime.utcnow() + timedelta(hours=hours)).isoformat(timespec="seconds")
    items[ip] = until
    state.put(db, KEY, items)
    return until


def is_trusted(db: Session, ip: str) -> bool:
    return ip in active(db)
