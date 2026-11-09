"""Rückbau des automatischen Sperrens: alle Sperren aufheben und die Zugriffsliste im Proxy Manager entfernen.

Der frühere Lückenwächter hat Dienste bei Lücken auf „nur Heimnetz“ gestellt. Das hat zu viele Dienste von außen
unerreichbar gemacht. Dieser Schritt stellt bei jedem Start (und danach alle 10 Minuten, bis alles erledigt ist)
den vorherigen Zustand wieder her.
"""
from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session

from . import notify, npm, state
from .database import engine
from .models import Quarantine

log = logging.getLogger("networkhelper.unquarantine")
OLD_TABLES = ("vuln_actions", "vuln_findings", "vulns", "inventory_targets")


def drop_old_tables() -> None:
    names = set(inspect(engine).get_table_names())
    with engine.begin() as c:
        for t in OLD_TABLES:
            if t in names:
                c.execute(text(f'DROP TABLE "{t}"'))
                log.info("Tabelle %s des alten Lückenwächters entfernt", t)


def pending(db: Session) -> list[Quarantine]:
    return list(db.scalars(select(Quarantine).where(Quarantine.released_at.is_(None))))


def run(db: Session) -> dict:
    if state.get(db, "unquarantine_done"):
        return {"done": True}
    open_q = pending(db)
    if not npm.configured():
        return {"done": False, "open": len(open_q), "error": "Proxy Manager nicht verbunden"}
    freed, errors = [], []
    npm.forget_hosts()
    try:
        hosts = {h["id"]: h for h in npm.raw_proxy_hosts()}
        list_id = npm.find_access_list(npm.QUARANTINE_LIST)
    except npm.NpmError as e:
        return {"done": False, "open": len(open_q), "error": str(e)}
    # 1. gespeicherte Sperren: vorherige Zugriffsliste wiederherstellen
    for q in open_q:
        h = hosts.get(q.proxy_host_id)
        try:
            if h and (list_id is None or h.get("access_list_id") == list_id):
                npm.set_access_list(q.proxy_host_id, q.prev_access_list_id)
                freed.append(q.domains)
            q.released_at, q.released_by, q.error = datetime.utcnow(), "Rückbau Lückenwächter", None
        except npm.NpmError as e:
            q.error = str(e)[:300]
            errors.append(f"{q.domains}: {e}")
    # 2. Hosts, die die Liste noch tragen (z. B. Sperre ohne Eintrag): wieder öffentlich
    if list_id is not None:
        for h in hosts.values():
            if h.get("access_list_id") == list_id and not any(d in " ".join(freed) for d in h["domains"]):
                try:
                    npm.set_access_list(h["id"], 0)
                    freed.append(", ".join(h["domains"]))
                except npm.NpmError as e:
                    errors.append(f"{h['domains'][0]}: {e}")
        if not errors:
            try:
                npm.delete_access_list(list_id)
            except npm.NpmError as e:
                errors.append(f"Zugriffsliste: {e}")
    db.commit()
    if freed:
        notify.raise_alert(db, "warn", "apps", f"Wieder erreichbar: {len(freed)} {'Dienst' if len(freed) == 1 else 'Dienste'}",
                           "Das automatische Sperren bei Lücken ist entfernt. Freigegeben: " + "; ".join(freed),
                           dedupe_key="unquarantine", dedupe_hours=24 * 365)
    if not errors:
        state.put(db, "unquarantine_done", datetime.utcnow().isoformat())
    return {"done": not errors, "freed": freed, "errors": errors}
