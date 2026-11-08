"""Warnungen: werden in der Datenbank gesammelt, im Dashboard angezeigt und per E-Mail verschickt.

Gleiche Warnungen (gleicher dedupe_key) entstehen innerhalb des Zeitfensters nur einmal. Kritische Warnungen gehen
sofort raus, andere werden kurz gesammelt und in einer Mail zusammengefasst, damit ein Ausfall mehrerer Dienste
nicht zehn Mails auslöst.
"""
from __future__ import annotations

import logging
import smtplib
import ssl
import threading
from datetime import datetime, timedelta
from email.message import EmailMessage

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .database import SessionLocal
from .models import Alert, User

log = logging.getLogger("networkhelper.notify")

RANK = {"info": 0, "warn": 1, "crit": 2}
SEVERITY_TEXT = {"info": "Hinweis", "warn": "Warnung", "crit": "Kritisch"}
BATCH_WAIT = timedelta(minutes=3)


def smtp_configured() -> bool:
    return bool(settings.smtp_host and (settings.smtp_from or settings.smtp_user))


def raise_alert(db: Session, severity: str, kind: str, title: str, body: str = "", dedupe_key: str | None = None,
                dedupe_hours: float = 6, commit: bool = True) -> Alert | None:
    """Legt eine Warnung an, außer es gab dieselbe (dedupe_key) innerhalb von dedupe_hours."""
    if dedupe_key:
        since = datetime.utcnow() - timedelta(hours=dedupe_hours)
        dup = db.scalar(select(Alert.id).where(Alert.dedupe_key == dedupe_key, Alert.created_at >= since).limit(1))
        if dup:
            return None
    alert = Alert(severity=severity, kind=kind, title=title[:200], body=body or None, dedupe_key=dedupe_key)
    db.add(alert)
    if commit:
        db.commit()
    if push_configured() and RANK.get(severity, 0) >= RANK.get(settings.ntfy_min_level, 1):
        threading.Thread(target=_push_quiet, args=(severity, kind, title, body), daemon=True).start()
    return alert


# ---------- Push über ntfy ----------

PRIORITY = {"info": 3, "warn": 4, "crit": 5}
TAGS = {"info": ["information_source"], "warn": ["warning"], "crit": ["rotating_light"]}
LINKS = {"vuln": "/security?tab=vulns", "proxmox": "/security?tab=proxmox", "adguard": "/dns?tab=adguard",
         "cert": "/security?tab=sites", "uptime": "/uptime"}


def push_configured() -> bool:
    return bool(settings.ntfy_topic)


def push(title: str, body: str = "", severity: str = "warn", kind: str = "", actions: list[dict] | None = None) -> None:
    """Schickt eine Push-Nachricht an die ntfy-App. Wirft httpx.HTTPError bei Fehlern."""
    link = settings.public_url.rstrip("/") + LINKS.get(kind, "/")
    payload = {"topic": settings.ntfy_topic, "title": title[:250], "message": (body or title)[:3500],
               "priority": PRIORITY.get(severity, 3), "tags": TAGS.get(severity, []), "click": link,
               "actions": actions or [{"action": "view", "label": "Öffnen", "url": link}]}
    headers = {"Authorization": f"Bearer {settings.ntfy_token}"} if settings.ntfy_token else {}
    r = httpx.post(settings.ntfy_url.rstrip("/"), json=payload, headers=headers, timeout=15)
    if r.status_code in (401, 403):
        raise httpx.HTTPStatusError("ntfy lehnt ab: Zugangstoken fehlt oder darf nicht in dieses Thema schreiben.", request=r.request, response=r)
    r.raise_for_status()


def _push_quiet(severity, kind, title, body):
    try:
        push(title, body, severity, kind)
    except httpx.HTTPError as e:
        log.warning("Push an ntfy fehlgeschlagen: %s", e)


def send_email(to: str | list[str], title: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = title
    msg["From"] = settings.smtp_from or settings.smtp_user
    msg["To"] = to if isinstance(to, str) else ", ".join(to)
    msg.set_content(f"{body}\n\n{settings.public_url}")
    if settings.smtp_port == 465:
        server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=20, context=ssl.create_default_context())
    else:
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20)
    with server as s:
        if settings.smtp_port != 465 and settings.smtp_starttls:
            s.starttls(context=ssl.create_default_context())
        if settings.smtp_user:
            s.login(settings.smtp_user, settings.smtp_password)
        s.send_message(msg)


def recipients(db: Session) -> list[str]:
    users = db.scalars(select(User).where(User.active.is_not(False))).all()
    out = []
    for u in users:
        wants = u.alert_email if u.alert_email is not None else (u.role == "admin")
        if wants:
            out.append(u.email)
    return out


def format_batch(alerts: list[Alert]) -> tuple[str, str]:
    alerts = sorted(alerts, key=lambda a: (-RANK.get(a.severity, 0), a.created_at))
    top = alerts[0]
    if len(alerts) == 1:
        title = f"NetworkHelper: {top.title}"
    else:
        crit = sum(1 for a in alerts if a.severity == "crit")
        title = f"NetworkHelper: {len(alerts)} Meldungen" + (f", {crit} kritisch" if crit else "")
    lines = []
    for a in alerts:
        lines.append(f"[{SEVERITY_TEXT.get(a.severity, a.severity)}] {a.title}")
        if a.body:
            lines.extend("    " + line for line in a.body.splitlines())
        lines.append("")
    return title, "\n".join(lines).rstrip()


def send_pending(db: Session | None = None, now: datetime | None = None) -> int:
    """Verschickt offene Warnungen. Gibt die Zahl der verschickten Warnungen zurück."""
    own = db is None
    db = db or SessionLocal()
    now = now or datetime.utcnow()
    try:
        pending = db.scalars(select(Alert).where(Alert.sent_at.is_(None)).order_by(Alert.id)).all()
        if not pending:
            return 0
        threshold = RANK.get(settings.alert_min_severity, 1)
        due, skip = [], []
        for a in pending:
            (due if RANK.get(a.severity, 0) >= threshold else skip).append(a)
        for a in skip:  # unter der Schwelle: nur im Dashboard
            a.sent_at, a.send_error = now, "nur im Dashboard"
        if not due:
            db.commit()
            return 0
        if not any(a.severity == "crit" for a in due) and now - min(a.created_at for a in due) < BATCH_WAIT:
            db.commit()
            return 0
        to = recipients(db)
        if not smtp_configured() or not to:
            reason = "E-Mail-Versand nicht eingerichtet" if not smtp_configured() else "kein Empfänger"
            for a in due:
                a.sent_at, a.send_error = now, reason
            db.commit()
            return 0
        title, body = format_batch(due)
        try:
            send_email(to, title, body)
        except Exception as e:  # beim nächsten Lauf erneut versuchen, aber nicht endlos
            log.warning("Warnmail fehlgeschlagen: %s", e)
            for a in due:
                a.send_error = str(e)[:300]
                if now - a.created_at > timedelta(hours=6):
                    a.sent_at = now
            db.commit()
            return 0
        for a in due:
            a.sent_at, a.send_error = now, None
        db.commit()
        return len(due)
    finally:
        if own:
            db.close()
