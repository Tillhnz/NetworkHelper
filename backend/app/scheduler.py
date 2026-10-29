"""Hintergrundaufgaben in zwei Spuren: eine schnelle (Erreichbarkeit, Erkennung, Mails) und eine langsame
(Portscan, Zertifikate, DNS, Aufräumen), damit ein langer Scan die Überwachung nicht aufhält."""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Callable

from sqlalchemy import delete, select

from . import adguard, appversions, certs, proxmox, detect, dns, domainguard, exposure, geoblock, report, geoip, notify, npm, porkbun, portscan, sitecheck, uptime
from .config import settings
from .database import SessionLocal
from .models import AccessEvent, Agent, Alert, DynRecord, Incident, MonitorResult

log = logging.getLogger("networkhelper.jobs")

AGENT_OFFLINE = timedelta(minutes=5)


class Job:
    def __init__(self, name: str, fn: Callable, interval: Callable[[], float], enabled: Callable[[], bool] = lambda: True, delay: float = 0):
        self.name, self.fn, self.interval, self.enabled = name, fn, interval, enabled
        self.next = time.monotonic() + delay
        self.last_run: datetime | None = None
        self.last_error: str | None = None
        self.running = False
        self.lock = threading.Lock()

    def run(self) -> None:
        if not self.lock.acquire(blocking=False):
            return  # läuft schon (zum Beispiel per Knopf gestartet)
        self.running = True
        try:
            with SessionLocal() as db:
                self.fn(db)
            self.last_error = None
        except Exception as e:  # noqa: BLE001 – Aufgabe beim nächsten Mal erneut versuchen
            log.exception("Aufgabe %s fehlgeschlagen", self.name)
            self.last_error = f"{e.__class__.__name__}: {e}"[:300]
        finally:
            self.last_run = datetime.utcnow()
            self.running = False
            self.lock.release()


def _maintenance(db) -> None:
    now = datetime.utcnow()
    detect.forget_own(db)
    db.execute(delete(AccessEvent).where(AccessEvent.ts < now - timedelta(days=settings.retention_days)))
    db.execute(delete(MonitorResult).where(MonitorResult.ts < now - timedelta(days=90)))
    db.execute(delete(Alert).where(Alert.created_at < now - timedelta(days=90)))
    db.execute(delete(Incident).where(Incident.last_seen < now - timedelta(days=180)))
    db.commit()
    detect.prune_blocks(db)
    geoip.refresh_if_old()


def _agents(db) -> None:
    now = datetime.utcnow()
    for a in db.scalars(select(Agent).where(Agent.last_seen.is_not(None))):
        if now - a.last_seen > AGENT_OFFLINE:
            notify.raise_alert(db, "warn", "agent", f"Agent „{a.name}“ meldet sich nicht mehr",
                               f"Zuletzt gesehen: {a.last_seen:%d.%m.%Y %H:%M} UTC. Zugriffe und Verbindungen dieses Servers fehlen.\n"
                               "Prüfe auf dem Server: systemctl status networkhelper-agent",
                               dedupe_key=f"agent-offline:{a.id}:{a.last_seen:%Y%m%d%H%M}", dedupe_hours=24)


def _dyndns_enabled() -> bool:
    if not (settings.dyndns_enabled and porkbun.configured()):
        return False
    with SessionLocal() as db:
        return db.scalar(select(DynRecord.id).where(DynRecord.enabled.is_(True)).limit(1)) is not None


FAST = [
    Job("uptime", uptime.run_due, lambda: 10, delay=20),
    Job("detect", detect.run, lambda: 30, delay=30),
    Job("alerts", notify.send_pending, lambda: 60, delay=45),
    Job("agents", _agents, lambda: 120, delay=300),
    Job("adguard", adguard.run, lambda: 600, adguard.configured, delay=75),
    Job("weekly_report", report.run, lambda: 900, lambda: settings.weekly_report, delay=600),
]
SLOW = [
    Job("npm_sync", dns.sync_from_npm, lambda: 600, npm.configured, delay=40),
    Job("dyndns", dns.run_dyndns, lambda: settings.dyndns_interval_min * 60, _dyndns_enabled, delay=60),
    Job("proxmox", proxmox.run, lambda: 1800, lambda: proxmox.configured() and bool(settings.proxmox_fingerprint), delay=100),
    Job("certs", certs.run, lambda: 6 * 3600, lambda: settings.cert_auto_renew and npm.configured(), delay=200),
    Job("sitecheck", sitecheck.run, lambda: settings.site_check_interval_h * 3600, delay=120),
    Job("domainguard", domainguard.run, lambda: 24 * 3600, porkbun.configured, delay=150),
    Job("feeds", geoblock.refresh_feeds, lambda: 24 * 3600, lambda: bool(geoblock.enabled_feeds()), delay=90),
    Job("appversions", appversions.run, lambda: 12 * 3600, lambda: settings.app_check_enabled, delay=300),
    Job("exposure", exposure.run, lambda: settings.exposure_interval_h * 3600, lambda: settings.exposure_enabled, delay=240),
    Job("portscan", portscan.run, lambda: settings.scan_interval_h * 3600, lambda: settings.scan_enabled, delay=180),
    Job("maintenance", _maintenance, lambda: 6 * 3600, delay=5),
]
JOBS = {j.name: j for j in FAST + SLOW}


def _lane(jobs: list[Job]) -> None:
    while True:
        now = time.monotonic()
        for j in jobs:
            if now >= j.next:
                j.next = now + max(5, j.interval())
                try:
                    if j.enabled():
                        j.run()
                except Exception:  # noqa: BLE001
                    log.exception("Aufgabe %s", j.name)
        time.sleep(2)


def start() -> None:
    threading.Thread(target=_lane, args=(FAST,), daemon=True, name="jobs-fast").start()
    threading.Thread(target=_lane, args=(SLOW,), daemon=True, name="jobs-slow").start()


def trigger(name: str) -> bool:
    """Startet eine Aufgabe sofort im Hintergrund. False, wenn sie gerade läuft."""
    job = JOBS[name]
    if job.running:
        return False
    threading.Thread(target=job.run, daemon=True, name=f"job-{name}").start()
    return True


def status() -> list[dict]:
    return [{"name": j.name, "last_run": j.last_run.isoformat() if j.last_run else None, "error": j.last_error,
             "running": j.running} for j in JOBS.values()]
