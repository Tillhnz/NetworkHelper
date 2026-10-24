"""Erreichbarkeit der Dienste: regelmäßige HTTP-Abrufe mit Verlauf.

Ein Dienst gilt erst nach zwei Fehlschlägen hintereinander als ausgefallen, damit ein einzelner Aussetzer keine
Warnung auslöst. Fällt er aus oder ist er wieder da, entsteht eine Meldung.
"""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import httpx
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from . import notify
from .config import settings
from .models import Monitor, MonitorResult

FAILS_FOR_DOWN = 2


def status_ok(status: int, expect: str) -> bool:
    """expect: '200-399', '200,204', '200-299,401'."""
    for part in re.split(r"[,\s]+", expect.strip() or "200-399"):
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            if lo.isdigit() and hi.isdigit() and int(lo) <= status <= int(hi):
                return True
        elif part.isdigit() and int(part) == status:
            return True
    return False


def probe(url: str, expect: str, keyword: str | None, verify: bool) -> dict:
    t0 = time.perf_counter()
    try:
        r = httpx.get(url, timeout=12, follow_redirects=True, verify=verify, headers={"User-Agent": "NetworkHelper-Uptime/1.0"})
        ms = int((time.perf_counter() - t0) * 1000)
        ok = status_ok(r.status_code, expect)
        err = None if ok else f"Antwort {r.status_code}, erwartet {expect}"
        if ok and keyword and keyword not in r.text:
            ok, err = False, f"Text „{keyword}“ nicht gefunden"
        return {"ok": ok, "latency_ms": ms, "status": r.status_code, "error": err}
    except httpx.TimeoutException:
        return {"ok": False, "latency_ms": None, "status": None, "error": "Zeitüberschreitung (12 s)"}
    except httpx.ConnectError as e:
        msg = str(e)
        if "CERTIFICATE_VERIFY_FAILED" in msg:
            return {"ok": False, "latency_ms": None, "status": None, "error": "Zertifikat ungültig"}
        return {"ok": False, "latency_ms": None, "status": None, "error": "Keine Verbindung"}
    except httpx.HTTPError as e:
        return {"ok": False, "latency_ms": None, "status": None, "error": e.__class__.__name__}


def _duration(delta: timedelta) -> str:
    s = int(delta.total_seconds())
    if s < 120:
        return f"{s} Sekunden"
    if s < 7200:
        return f"{s // 60} Minuten"
    return f"{s // 3600} Stunden {s % 3600 // 60} Minuten"


def apply_result(db: Session, m: Monitor, res: dict, now: datetime) -> None:
    db.add(MonitorResult(monitor_id=m.id, ts=now, ok=res["ok"], latency_ms=res["latency_ms"], status=res["status"], error=res["error"]))
    m.last_check, m.last_latency_ms, m.last_status, m.last_error = now, res["latency_ms"], res["status"], res["error"]
    if res["ok"]:
        if m.state == "down":
            since = m.changed_at or now
            notify.raise_alert(db, "info", "uptime", f"{m.name} ist wieder erreichbar", f"Ausfall: {_duration(now - since)}\n{m.url}",
                               dedupe_key=f"up:{m.id}:{now:%Y%m%d%H%M}", dedupe_hours=0.1)
        if m.state != "up":
            m.changed_at = now
        m.state, m.fails = "up", 0
    else:
        m.fails = (m.fails or 0) + 1
        if m.fails >= FAILS_FOR_DOWN and m.state != "down":
            m.state, m.changed_at = "down", now
            notify.raise_alert(db, "crit", "uptime", f"{m.name} ist nicht erreichbar", f"{res['error']}\n{m.url}",
                               dedupe_key=f"down:{m.id}:{now:%Y%m%d%H}", dedupe_hours=0.5)


def run_due(db: Session, force_ids: list[int] | None = None) -> int:
    now = datetime.utcnow()
    interval = timedelta(seconds=settings.monitor_interval_s)
    mons = db.scalars(select(Monitor).where(Monitor.enabled.is_(True))).all()
    due = [m for m in mons if (force_ids and m.id in force_ids) or (not force_ids and (m.last_check is None or now - m.last_check >= interval - timedelta(seconds=5)))]
    if not due:
        return 0
    with ThreadPoolExecutor(max_workers=min(16, len(due))) as pool:
        results = list(pool.map(lambda m: probe(m.url, m.expect, m.keyword, m.verify_tls), due))
    for m, res in zip(due, results):
        apply_result(db, m, res, now)
    db.commit()
    return len(due)


def history(db: Session, monitor_id: int, hours: int = 24, buckets: int = 48) -> list[dict]:
    """Verlauf in gleich großen Abschnitten: Anteil erfolgreicher Prüfungen und mittlere Antwortzeit."""
    now = datetime.utcnow()
    start = now - timedelta(hours=hours)
    rows = db.execute(select(MonitorResult.ts, MonitorResult.ok, MonitorResult.latency_ms)
                      .where(MonitorResult.monitor_id == monitor_id, MonitorResult.ts >= start)).all()
    size = hours * 3600 / buckets
    acc = [[0, 0, 0, 0] for _ in range(buckets)]  # gesamt, ok, latenz-summe, latenz-anzahl
    for ts, ok, lat in rows:
        i = min(buckets - 1, int((ts - start).total_seconds() // size))
        acc[i][0] += 1
        acc[i][1] += 1 if ok else 0
        if lat is not None:
            acc[i][2] += lat
            acc[i][3] += 1
    return [{"t": (start + timedelta(seconds=size * i)).isoformat(), "checks": a[0], "up": (a[1] / a[0]) if a[0] else None,
             "latency": round(a[2] / a[3]) if a[3] else None} for i, a in enumerate(acc)]


def uptime_pct(db: Session, monitor_id: int, days: int) -> float | None:
    since = datetime.utcnow() - timedelta(days=days)
    total, up = db.execute(select(func.count(), func.sum(case((MonitorResult.ok.is_(True), 1), else_=0)))
                           .where(MonitorResult.monitor_id == monitor_id, MonitorResult.ts >= since)).one()
    if not total:
        return None
    return round(100 * (up or 0) / total, 2)
