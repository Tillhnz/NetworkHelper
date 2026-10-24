"""Wochenbericht per E-Mail: alles grün, oder diese Dinge solltest du ansehen."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from . import notify, publicip, state
from .config import settings
from .models import AccessEvent, Incident, Monitor, SiteCheck

log = logging.getLogger("networkhelper.report")
LEVEL = {"ok": "Grün: alles in Ordnung", "warn": "Gelb: ein paar Dinge verbessern", "crit": "Rot: bitte bald ansehen"}


def _n(x) -> str:
    return f"{int(x or 0):,}".replace(",", ".")


def build(db: Session, now: datetime | None = None) -> tuple[str, str]:
    from . import classify as cls
    from .routers.overview import security_status
    now = now or datetime.utcnow()
    since = now - timedelta(days=7)
    sec = security_status(db)
    E = AccessEvent
    total, uniq = db.execute(select(func.count(), func.count(distinct(E.ip))).where(E.ts >= since)).one()
    external = db.scalar(select(func.count()).where(E.ts >= since, E.as_org.is_distinct_from("Heimnetz"))) or 0
    blocked = db.scalar(select(func.count()).where(E.ts >= since, E.blocked.is_(True))) or 0
    countries = db.execute(select(E.country, func.count()).where(E.ts >= since, E.country.is_not(None))
                           .group_by(E.country).order_by(func.count().desc()).limit(5)).all()
    incidents = db.execute(select(Incident.kind, func.count(distinct(Incident.ip))).where(Incident.last_seen >= since)
                           .group_by(Incident.kind)).all()
    groups = {}
    for c in cls.summarize(cls.classify_ips(db, since, publicip.info(db).get("ip"), limit=2000)):
        groups[c["group"]] = groups.get(c["group"], 0) + c["count"]
    down = db.scalars(select(Monitor.name).where(Monitor.enabled.is_(True), Monitor.state == "down")).all()
    soon = db.scalars(select(SiteCheck).where(SiteCheck.enabled.is_(True), SiteCheck.cert_expires.is_not(None),
                                              SiteCheck.cert_expires < now + timedelta(days=21))).all()
    apps = [i for i in (state.get(db, "appversions") or {}).get("items", []) if i.get("status") in ("vulnerable", "major", "minor", "patch")]

    todo = [r for r in sec["reasons"] if r["level"] in ("crit", "warn")]
    title = "NetworkHelper Wochenbericht: " + ("alles in Ordnung" if not todo else f"{len(todo)} {'Punkt' if len(todo) == 1 else 'Punkte'} zum Ansehen")
    L = [f"Sicherheit: {sec['score']} von 100 Punkten. {LEVEL.get(sec['level'], '')}", ""]
    if todo:
        L.append("Das solltest du dir ansehen:")
        L += [f"  {'!' if r['level'] == 'crit' else '-'} {r['text']}" for r in todo[:10]]
        L.append("")
    L.append("Die letzte Woche")
    L.append(f"  {_n(total)} Zugriffe von {_n(uniq)} Adressen, davon {_n(external)} von außen und {_n(blocked)} abgewiesen.")
    if groups:
        names = {"friendly": "du und deine Nutzer", "service": "nützliche Dienste", "noise": "automatisch, meist harmlos", "attack": "Angriffsversuche"}
        part = ", ".join(f"{names[g]} {_n(groups[g])}" for g in ("friendly", "service", "noise", "attack") if groups.get(g))
        L.append(f"  Wer: {part}.")
    if countries:
        L.append("  Häufigste Länder: " + ", ".join(f"{c or '?'} ({_n(n)})" for c, n in countries) + ".")
    if incidents:
        kinds = {"scanner": "Schwachstellen-Suchen", "bruteforce": "Passwort-Angriffe", "badagent": "Angriffswerkzeuge",
                 "notfound": "Verzeichnis-Scans", "flood": "Überflutungen"}
        L.append("  Erkannte Angriffe (Adressen): " + ", ".join(f"{kinds.get(k, k)} {n}" for k, n in incidents) + ".")
    L.append("")
    if down:
        L.append("Gerade nicht erreichbar: " + ", ".join(down))
    for s in soon:
        L.append(f"Zertifikat von {s.host} läuft in {(s.cert_expires - now).days} Tagen ab.")
    if apps:
        L.append("Updates verfügbar: " + ", ".join(f"{a['name']} auf {a['host']} ({a.get('version')} → {str(a.get('latest') or '?').lstrip('v')})" for a in apps[:6]))
    if not (down or soon or apps):
        L.append("Alle Dienste erreichbar, keine Zertifikate kurz vor Ablauf, keine bekannten Updates offen.")
    L += ["", "Diesen Bericht abbestellen oder den Tag ändern: Administration → E-Mail."]
    return title, "\n".join(L)


def run(db: Session, now: datetime | None = None, force: bool = False) -> bool:
    """Stündlich aufgerufen; verschickt einmal pro Woche zum eingestellten Zeitpunkt."""
    now = now or datetime.utcnow()
    try:
        local = now.replace(tzinfo=ZoneInfo("UTC")).astimezone(ZoneInfo(settings.timezone))
    except Exception:  # noqa: BLE001 – unbekannte Zeitzone
        local = now
    week = f"{local.isocalendar()[0]}-{local.isocalendar()[1]}"
    if not force:
        if not settings.weekly_report or local.weekday() != settings.weekly_report_day or local.hour < settings.weekly_report_hour:
            return False
        if state.get(db, "weekly_report_week") == week:
            return False
    to = notify.recipients(db)
    if not notify.smtp_configured() or not to:
        state.put(db, "weekly_report_week", week)
        return False
    title, body = build(db, now)
    notify.send_email(to, title, body)
    state.put(db, "weekly_report_week", week)
    log.info("Wochenbericht an %d Empfänger verschickt", len(to))
    return True
