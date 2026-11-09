"""Speicherplatz: was die Datenbank belegt und wie man sie wieder verkleinert."""
from __future__ import annotations

import logging
import os
import threading
from datetime import datetime

from sqlalchemy import text

from .config import settings
from .database import engine

log = logging.getLogger("networkhelper.storage")
LABELS = {
    "access_events": "Zugriffe (Protokoll des Proxy Managers)", "monitor_results": "Erreichbarkeit (Messwerte)",
    "watch_events": "Wachsamkeit (Anmeldungen, Dateien)", "inventory_targets": "Inventur (Paketlisten)",
"alerts": "Meldungen", "kv_state": "Zwischenstände",
    "agents": "Agenten", "watch_state": "Wachsamkeit (Stand)", "audit_log": "Änderungsprotokoll", "incidents": "Vorfälle",
}
job = {"running": False, "started": None, "finished": None, "freed": None, "error": None}


def is_pg() -> bool:
    return engine.dialect.name == "postgresql"


def db_usage() -> dict:
    with engine.connect() as c:
        if is_pg():
            total = c.execute(text("SELECT pg_database_size(current_database())")).scalar()
            rows = c.execute(text(
                "SELECT relname, pg_total_relation_size(relid) AS size, n_live_tup, n_dead_tup "
                "FROM pg_stat_user_tables ORDER BY size DESC LIMIT 12")).all()
            tables = [{"name": r[0], "label": LABELS.get(r[0], r[0]), "size": int(r[1]), "rows": int(r[2] or 0), "dead": int(r[3] or 0)}
                      for r in rows]
        else:
            path = engine.url.database or ""
            total = os.path.getsize(path) if path and os.path.exists(path) else 0
            tables = []
    return {"total": int(total or 0), "tables": tables, "retention_days": settings.retention_days}


def _vacuum_full():
    job.update(running=True, started=datetime.utcnow().isoformat(), finished=None, error=None, freed=None)
    try:
        before = db_usage()["total"]
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as c:
            if is_pg():
                for t in ("access_events", "monitor_results", "watch_events", "alerts", "kv_state"):
                    try:
                        c.execute(text(f'VACUUM (FULL, ANALYZE) "{t}"'))
                    except Exception as e:  # noqa: BLE001 - Tabelle fehlt o. ä.
                        log.warning("VACUUM %s: %s", t, e)
            else:
                c.execute(text("VACUUM"))
        job["freed"] = max(0, before - db_usage()["total"])
    except Exception as e:  # noqa: BLE001
        job["error"] = str(e)[:300]
    finally:
        job.update(running=False, finished=datetime.utcnow().isoformat())


def start_shrink() -> bool:
    if job["running"]:
        return False
    threading.Thread(target=_vacuum_full, daemon=True, name="vacuum").start()
    return True
