"""Update-Wächter: meldet per Push, sobald auf GitHub eine neue Version von NetworkHelper bereitliegt.

Fragt alle 6 Stunden den Update-Dienst (git fetch) und meldet jede neue Version genau einmal. Enthält sie
Paket- oder Sicherheitsupdates (z. B. von Dependabot), kommt die Meldung mit höherer Priorität.
"""
from __future__ import annotations

import logging
import re

from fastapi import HTTPException
from sqlalchemy.orm import Session

from . import notify, state
from .config import settings

log = logging.getLogger("networkhelper.updatewatch")
SECURITY = re.compile(r"\b(bump|sicherheit|security|cve-|lücke|vulnerab|dependabot|pyjwt|cryptography)\b", re.I)


def describe(changes: list[str], behind: int) -> tuple[bool, str]:
    subjects = [c.split("  ", 1)[-1] for c in changes]
    sec = any(SECURITY.search(s) for s in subjects)
    lines = "\n".join(f"• {s}" for s in subjects[:8]) + (f"\n… und {behind - 8} weitere" if behind > 8 else "")
    return sec, lines


def run(db: Session) -> None:
    if not settings.update_notify:
        return
    from .routers.admin import _updater
    try:
        st = _updater("GET", "/status?check=1", timeout=120)
    except HTTPException as e:
        log.info("Update-Prüfung nicht möglich: %s", e.detail)
        return
    behind, changes = st.get("behind") or 0, st.get("changes") or []
    if not behind or not changes:
        return
    key = changes[0]
    if state.get(db, "update_notified") == key:
        return
    sec, lines = describe(changes, behind)
    title = ("Sicherheitsupdate" if sec else "Neue Version") + " für NetworkHelper verfügbar"
    body = (f"{behind} {'Änderung' if behind == 1 else 'Änderungen'}:\n{lines}\n\n"
            "Einspielen: Administration → Übersicht → Update.")
    notify.raise_alert(db, "warn" if sec else "info", "update", title, body, dedupe_key=f"update:{key}"[:200],
                       dedupe_hours=24 * 30, commit=False)
    if notify.push_configured() and notify.RANK.get("warn" if sec else "info", 0) < notify.RANK.get(settings.ntfy_min_level, 1):
        try:  # neue Versionen immer pushen, auch wenn sonst nur Warnungen gepusht werden
            notify.push(title, body, "warn" if sec else "info", "update")
        except Exception as e:  # noqa: BLE001
            log.warning("Push fehlgeschlagen: %s", e)
    state.put(db, "update_notified", key)
