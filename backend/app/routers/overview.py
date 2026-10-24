"""Startseite: Kennzahlen, Sicherheitsstatus und Meldungen auf einen Blick."""
import calendar
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from .. import npm, porkbun, portscan, publicip, state
from ..database import get_db
from ..models import AccessEvent, Agent, Alert, DynRecord, Incident, Monitor, PortFinding, SiteCheck, User
from ..security import current_user, require_admin
from .access import time_buckets

router = APIRouter(prefix="/api", tags=["overview"])


def security_status(db: Session) -> dict:
    """Ampel aus offenen Ports, Zertifikaten, Headern, Vorfällen und Ausfällen. Jeder Abzug wird begründet."""
    reasons = []
    expected = portscan.expected(db)
    open_ports = db.scalars(select(PortFinding).where(PortFinding.open.is_(True))).all()
    last = state.get(db, "portscan_last")
    seen = set()
    for f in open_ports:
        if f.port in expected or (f.target, f.port) in seen:
            continue
        seen.add((f.target, f.port))
        risky = f.port in portscan.RISKY
        name = f"Port {f.port} ({f.service or portscan.SERVICES.get(f.port, 'unbekannt')})"
        if portscan.outside_view(last, f.target, f.port, f.source) == "no":
            # nur aus dem Heimnetz gesehen: vermutlich ein Dienst des Routers selbst, kaum Abzug
            reasons.append({"points": 2, "level": "warn", "area": "ports", "text": f"{name} nur aus dem Heimnetz gesehen, bitte von außen prüfen"})
            continue
        reasons.append({"points": 25 if risky else 10, "level": "crit" if risky else "warn", "area": "ports",
                        "text": f"{name} offen auf {f.target}"})
    now = datetime.utcnow()
    sites = db.scalars(select(SiteCheck).where(SiteCheck.enabled.is_(True), SiteCheck.checked_at.is_not(None))).all()
    for s in sites:
        if s.cert_valid is False:
            reasons.append({"points": 30, "level": "crit", "area": "sites", "text": f"Ungültiges Zertifikat: {s.host}"})
        elif s.cert_expires and (s.cert_expires - now).days < 14:
            reasons.append({"points": 15, "level": "warn", "area": "sites", "text": f"Zertifikat von {s.host} läuft in {(s.cert_expires - now).days} Tagen ab"})
    weak = [s.host for s in sites if s.grade in ("D", "E", "F") and s.cert_valid is not False]
    if weak:
        reasons.append({"points": min(20, 5 * len(weak)), "level": "warn", "area": "sites",
                        "text": f"Schwache Sicherheits-Header: {', '.join(weak[:4])}{' …' if len(weak) > 4 else ''}"})
    crit = db.scalar(select(func.count()).select_from(Incident).where(Incident.acknowledged.is_(False), Incident.severity == "crit",
                                                                       Incident.last_seen >= now - timedelta(days=1))) or 0
    if crit:
        reasons.append({"points": 10, "level": "crit", "area": "incidents", "text": f"{crit} offene kritische Vorfälle (Anmeldeversuche)"})
    from ..models import Exposure, User, WatchEvent
    hw = db.execute(select(Agent.name, WatchEvent.severity, func.count()).join(Agent, Agent.id == WatchEvent.agent_id)
                    .where(WatchEvent.acknowledged.is_(False), WatchEvent.severity.in_(["warn", "crit"]))
                    .group_by(Agent.name, WatchEvent.severity)).all()
    for name, sev, n in hw:
        reasons.append({"points": 25 if sev == "crit" else 5, "level": sev, "area": "host",
                        "text": f"{n} {'wichtige ' if sev == 'crit' else ''}Auffälligkeit{'en' if n > 1 else ''} auf {name}, bitte bestätigen oder prüfen"})
    for d in (state.get(db, "domainguard") or {}).get("domains", []):
        for c in d.get("checks", []):
            if not c["ok"] and c["severity"] in ("warn", "crit"):
                reasons.append({"points": 15 if c["severity"] == "crit" else 3, "level": c["severity"], "area": "domain",
                                "text": f"{d['domain']}: {c['label']} fehlt oder ist zu locker"})
    for it in (state.get(db, "appversions") or {}).get("items", []):
        if it.get("status") == "vulnerable":
            worst = "crit" if any(a["severity"] in ("critical", "high") for a in it.get("advisories", [])) else "warn"
            reasons.append({"points": 20 if worst == "crit" else 10, "level": worst, "area": "apps",
                            "text": f"{it['name']} {it.get('version')} auf {it['host']} hat bekannte Sicherheitslücken"})
        elif it.get("status") == "major":
            reasons.append({"points": 3, "level": "warn", "area": "apps", "text": f"{it['name']} auf {it['host']} ist eine Hauptversion zurück"})
    no2fa = db.scalars(select(User.email).where(User.role == "admin", User.active.is_not(False), User.totp_enabled.is_not(True))).all()
    if no2fa:
        reasons.append({"points": 5, "level": "warn", "area": "account",
                        "text": f"Administrator ohne Zwei-Faktor-Anmeldung: {', '.join(no2fa[:3])}"})
    for e in db.scalars(select(Exposure).where(Exposure.fixed_at.is_(None), Exposure.acknowledged.is_(False))):
        if e.result == "exposed":
            pts = 40 if e.severity == "crit" else 10
            extra = f", {e.attacked}× von Fremden abgerufen" if e.attacked else ""
            reasons.append({"points": pts, "level": "crit" if e.severity == "crit" else "warn", "area": "exposure",
                            "text": f"{e.label} lesbar: {e.host}{e.path}{extra}"})
        else:
            reasons.append({"points": 3, "level": "warn", "area": "exposure", "text": f"Unklare Datei prüfen: {e.host}{e.path}"})
    down = db.scalars(select(Monitor.name).where(Monitor.enabled.is_(True), Monitor.state == "down")).all()
    if down:
        reasons.append({"points": 10, "level": "crit", "area": "uptime", "text": f"Nicht erreichbar: {', '.join(down[:4])}"})
    score = max(0, 100 - sum(r["points"] for r in reasons))
    level = "ok" if score >= 80 else "warn" if score >= 50 else "crit"
    reasons.sort(key=lambda r: -r["points"])
    return {"score": score, "level": level, "reasons": reasons}


@router.get("/overview")
def overview(user: User = Depends(current_user), db: Session = Depends(get_db)):
    now = datetime.utcnow()
    since = now - timedelta(hours=24)
    E = AccessEvent
    conds = [E.ts >= since]
    total, uniq = db.execute(select(func.count(), func.count(distinct(E.ip))).where(*conds)).one()
    external = db.scalar(select(func.count()).where(*conds, E.as_org.is_distinct_from("Heimnetz"))) or 0
    errors = db.scalar(select(func.count()).where(*conds, E.status >= 400)) or 0
    blocked = db.scalar(select(func.count()).where(*conds, E.blocked.is_(True))) or 0
    size = 3600
    start = calendar.timegm(since.timetuple()) // size * size
    bucket, klass = time_buckets(db, size)
    rows = db.execute(select(bucket, klass, func.count()).where(*conds).group_by(bucket, klass)).all()
    series = [{"t": datetime.utcfromtimestamp(start + i * size).isoformat(), "2": 0, "3": 0, "4": 0, "5": 0} for i in range(25)]
    for b, k, c in rows:
        i = int(b) - start // size
        if 0 <= i < 25 and str(k) in "2345":
            series[i][str(k)] += c
    top_hosts = db.execute(select(E.host, func.count()).where(*conds).group_by(E.host).order_by(func.count().desc()).limit(6)).all()
    countries = db.execute(select(E.country, func.count()).where(*conds, E.country.is_not(None)).group_by(E.country).order_by(func.count().desc()).limit(6)).all()

    mons = db.scalars(select(Monitor).where(Monitor.enabled.is_(True)).order_by(Monitor.name)).all()
    agents = db.scalars(select(Agent)).all()
    sites = db.scalars(select(SiteCheck).where(SiteCheck.enabled.is_(True), SiteCheck.cert_expires.is_not(None))).all()
    next_cert = min(sites, key=lambda s: s.cert_expires, default=None)
    incidents = db.scalars(select(Incident).where(Incident.last_seen >= since).order_by(Incident.last_seen.desc()).limit(6)).all()
    open_inc = db.scalar(select(func.count()).select_from(Incident).where(Incident.acknowledged.is_(False), Incident.last_seen >= now - timedelta(days=7))) or 0
    dyn_err = db.scalar(select(func.count()).select_from(DynRecord).where(DynRecord.last_error.is_not(None))) or 0
    alerts = db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(8)).all()
    return {
        "access": {"total": total or 0, "unique_ips": uniq or 0, "external": external, "errors": errors, "blocked": blocked, "series": series,
                   "hosts": [{"host": h, "count": c} for h, c in top_hosts], "countries": [{"country": k, "count": c} for k, c in countries]},
        "monitors": {"total": len(mons), "up": sum(1 for m in mons if m.state == "up"), "down": [{"id": m.id, "name": m.name, "error": m.last_error, "since": m.changed_at.isoformat() if m.changed_at else None} for m in mons if m.state == "down"],
                     "items": [{"id": m.id, "name": m.name, "state": m.state, "latency_ms": m.last_latency_ms} for m in mons]},
        "security": security_status(db),
        "certs": {"next": {"host": next_cert.host, "days": (next_cert.cert_expires - now).days} if next_cert else None, "count": len(sites)},
        "incidents": {"open": open_inc, "recent": [{"id": i.id, "ip": i.ip, "kind": i.kind, "severity": i.severity, "count": i.count,
                                                     "country": i.country, "last_seen": i.last_seen.isoformat()} for i in incidents]},
        "agents": {"total": len(agents), "online": sum(1 for a in agents if a.last_seen and now - a.last_seen < timedelta(minutes=3))},
        "npm_configured": npm.configured(),
        "dns": {"configured": porkbun.configured(), "public_ip": publicip.info(db), "dyn_records": db.scalar(select(func.count()).select_from(DynRecord)) or 0, "dyn_errors": dyn_err,
                "last": state.get(db, "dyndns_last")},
        "portscan": state.get(db, "portscan_last"),
        "alerts": [_alert(a) for a in alerts],
    }


def _alert(a: Alert) -> dict:
    return {"id": a.id, "created_at": a.created_at.isoformat(), "severity": a.severity, "kind": a.kind, "title": a.title,
            "body": a.body, "sent_at": a.sent_at.isoformat() if a.sent_at else None, "send_error": a.send_error, "read": a.read}


@router.get("/alerts")
def alerts(limit: int = 100, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(max(1, min(limit, 500)))).all()
    unread = db.scalar(select(func.count()).select_from(Alert).where(Alert.read.is_(False))) or 0
    return {"items": [_alert(a) for a in rows], "unread": unread}


@router.post("/alerts/read", status_code=204)
def mark_read(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    for a in db.scalars(select(Alert).where(Alert.read.is_(False))):
        a.read = True
    db.commit()


@router.delete("/alerts/{alert_id}", status_code=204)
def delete_alert(alert_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    a = db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(404, "Meldung nicht gefunden")
    db.delete(a)
    db.commit()


@router.get("/setup/status")
def setup_status(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Einrichtungsstand für den Assistenten: was ist schon verbunden, was fehlt noch."""
    from .. import notify
    now = datetime.utcnow()
    agents = db.scalars(select(Agent)).all()
    online = [a for a in agents if a.last_seen and now - a.last_seen < timedelta(minutes=3)]
    with_logs = [a for a in agents if (a.lines_total or 0) > 0]
    return {
        "agents": {"total": len(agents), "online": len(online), "with_logs": len(with_logs),
                   "names": [a.name for a in online]},
        "npm": npm.configured(),
        "porkbun": porkbun.configured(),
        "smtp": notify.smtp_configured(),
        "monitors": db.scalar(select(func.count()).select_from(Monitor)) or 0,
        "public_ip": publicip.info(db).get("ip"),
    }
