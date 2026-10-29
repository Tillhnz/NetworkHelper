"""Administration: Konten, Einladungen, Servereinstellungen, Updates, Sicherungen, Protokoll, Zustand."""
import hashlib
import json
import os
import platform
import secrets
import shutil
import time
import urllib.error
import urllib.request
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .. import adguard, audit, proxmox, geoip, notify, npm, porkbun, publicip, scheduler, server_settings
from ..config import settings
from ..database import get_db
from ..models import AuditEntry, Invite, User
from ..security import require_admin

STARTED = time.time()

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _admin_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(User).where(User.role == "admin")) or 0


# ---------- Einladungen ----------

def _invite(i: Invite) -> dict:
    return {"id": i.id, "code": i.code, "used_by_email": i.used_by_email, "created_at": i.created_at.isoformat() if i.created_at else None}


@router.get("/invites")
def list_invites(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return [_invite(i) for i in db.scalars(select(Invite).order_by(Invite.id.desc()))]


@router.post("/invites", status_code=201)
def create_invite(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    invite = Invite(code=secrets.token_hex(5).upper())
    db.add(invite)
    db.commit()
    audit.record(db, admin.email, "invite.create", invite.code)
    return _invite(invite)


@router.delete("/invites/{invite_id}", status_code=204)
def delete_invite(invite_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    invite = db.get(Invite, invite_id)
    if invite is None:
        raise HTTPException(404, "Einladung nicht gefunden")
    db.delete(invite)
    db.commit()
    audit.record(db, admin.email, "invite.delete", invite.code)


# ---------- Konten ----------

class UserPatch(BaseModel):
    role: Literal["admin", "user"] | None = None
    active: bool | None = None


def _user_row(u: User, me: User) -> dict:
    return {"id": u.id, "email": u.email, "role": u.role or "user", "active": u.active is not False,
            "created_at": u.created_at.isoformat() if u.created_at else None, "is_me": u.id == me.id, "two_factor": bool(u.totp_enabled)}


@router.get("/users")
def list_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return [_user_row(u, admin) for u in db.scalars(select(User).order_by(User.id))]


@router.put("/users/{user_id}")
def update_user(user_id: int, data: UserPatch, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "Konto nicht gefunden")
    if target.id == admin.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "Die eigene Rolle und das eigene Konto änderst du nicht selbst.")
    if data.role is not None and data.role != (target.role or "user"):
        if data.role == "user" and target.role == "admin" and _admin_count(db) <= 1:
            raise HTTPException(status.HTTP_409_CONFLICT, "Es muss mindestens ein Administrator bleiben.")
        target.role = data.role
        audit.record(db, admin.email, "user.role", f"{target.email} -> {data.role}")
    if data.active is not None:
        target.active = data.active
        if not data.active:
            target.token_version = (target.token_version or 0) + 1
        audit.record(db, admin.email, "user.lock" if not data.active else "user.unlock", target.email)
    db.commit()
    return _user_row(target, admin)


@router.delete("/users/{user_id}/2fa")
def reset_two_factor(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Zwei-Faktor-Anmeldung eines anderen Kontos zurücksetzen (Handy verloren). Das Konto wird überall abgemeldet."""
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "Konto nicht gefunden")
    if target.id == admin.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "Deine eigene Zwei-Faktor-Anmeldung änderst du unter Einstellungen.")
    target.totp_enabled, target.totp_secret, target.totp_pending, target.recovery_codes, target.totp_enabled_at = False, None, None, None, None
    target.token_version = (target.token_version or 0) + 1
    db.commit()
    audit.record(db, admin.email, "user.2fa_reset", target.email)
    return _user_row(target, admin)


@router.delete("/users/{user_id}", status_code=204)
def remove_user(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if user_id == admin.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "Das eigene Konto löschst du unter Einstellungen.")
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "Konto nicht gefunden")
    if target.role == "admin" and _admin_count(db) <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "Es muss mindestens ein Administrator bleiben.")
    email = target.email
    db.delete(target)
    db.commit()
    audit.record(db, admin.email, "user.delete", email)


# ---------- Servereinstellungen ----------

class SettingsIn(BaseModel):
    values: dict


def _settings_payload(db: Session) -> dict:
    return {"fields": server_settings.describe(db), "smtp_ready": notify.smtp_configured(),
            "porkbun_ready": porkbun.configured(), "npm_ready": npm.configured(),
            "adguard_ready": adguard.configured(), "proxmox_ready": proxmox.configured()}


@router.get("/settings")
def get_settings(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return _settings_payload(db)


@router.put("/settings")
def save_settings(data: SettingsIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        if data.values.get("two_factor_required") in (True, "true", "1", 1) and not admin.totp_enabled:
            raise server_settings.SettingError("Richte zuerst für dein eigenes Konto die Zwei-Faktor-Anmeldung ein, sonst sperrst du dich aus.")
        server_settings.save(db, data.values)
    except server_settings.SettingError as e:
        raise HTTPException(422, str(e))
    audit.record(db, admin.email, "settings.save", ", ".join(sorted(data.values))[:290])
    if ("geoip_enabled" in data.values or "geoip_city" in data.values) and settings.geoip_enabled:
        geoip.reload()  # Städte aus- oder einschalten wirkt sofort
        scheduler.trigger("maintenance")
    if any(k.startswith("feed_") for k in data.values):
        from .. import geoblock
        geoblock.invalidate()
        scheduler.trigger("feeds")
    if any(k.startswith("npm_") for k in data.values) and npm.configured():
        scheduler.trigger("npm_sync")
    return _settings_payload(db)


@router.get("/report/preview")
def report_preview(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    from .. import report
    title, body = report.build(db)
    return {"title": title, "body": body}


@router.post("/report/send")
def report_send(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Wochenbericht sofort an das eigene Konto schicken."""
    from .. import report
    if not notify.smtp_configured():
        raise HTTPException(409, "Der E-Mail-Versand ist noch nicht eingerichtet.")
    title, body = report.build(db)
    try:
        notify.send_email(admin.email, title, body)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"Versand fehlgeschlagen: {e}")
    return {"sent_to": admin.email}


@router.post("/settings/test-email")
def test_email(admin: User = Depends(require_admin)):
    if not notify.smtp_configured():
        raise HTTPException(422, "Trage zuerst Server und Absender- oder Benutzeradresse ein und speichere.")
    try:
        notify.send_email(admin.email, "NetworkHelper: Testmail", "Der E-Mail-Versand funktioniert. So sehen Warnungen später aus.")
    except Exception as e:
        raise HTTPException(502, f"Versand fehlgeschlagen: {e.__class__.__name__}: {e}")
    return {"ok": True, "to": admin.email}


@router.post("/settings/test-porkbun")
def test_porkbun(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        ip = porkbun.ping()
        domains = porkbun.managed_domains()
    except porkbun.PorkbunError as e:
        raise HTTPException(502, str(e))
    if ip:
        publicip.current(db, refresh=True)
    return {"ok": True, "ip": ip, "domains": domains}


@router.post("/settings/test-adguard")
def test_adguard(admin: User = Depends(require_admin)):
    try:
        st = adguard.status()
        stats = adguard.stats()
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))
    return {"ok": True, "version": st["version"], "protection": st["protection"], "queries": stats["queries"]}


@router.post("/settings/test-proxmox")
def test_proxmox(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        return proxmox.test()
    except proxmox.ProxmoxError as e:
        raise HTTPException(502, str(e))


class FingerprintIn(BaseModel):
    fingerprint: str = Field(..., max_length=120)


@router.post("/settings/proxmox-trust")
def trust_proxmox(data: FingerprintIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Bestätigt den angezeigten Fingerabdruck. Nur wenn der Server ihn gerade wirklich zeigt."""
    try:
        current = proxmox.fingerprint()
    except proxmox.ProxmoxError as e:
        raise HTTPException(502, str(e))
    if current.replace(":", "") != data.fingerprint.replace(":", "").upper():
        raise HTTPException(409, "Der Server zeigt inzwischen einen anderen Fingerabdruck. Bitte erneut testen.")
    server_settings.save(db, {"proxmox_fingerprint": current})
    audit.record(db, admin.email, "proxmox.trust", current[:23])
    scheduler.trigger("proxmox")
    return {"fingerprint": current}


@router.post("/settings/test-npm")
def test_npm(admin: User = Depends(require_admin)):
    try:
        hosts = npm.proxy_hosts()
    except npm.NpmError as e:
        raise HTTPException(502, str(e))
    scheduler.trigger("npm_sync")
    return {"ok": True, "hosts": len(hosts), "domains": sum(len(h["domains"]) for h in hosts)}


# ---------- Updates und Sicherungen (über den Update-Dienst) ----------

def _updater(method: str, path: str, timeout: float = 90):
    if not settings.updater_url:
        raise HTTPException(503, "Der Update-Dienst ist nicht eingerichtet. Führe einmalig ./install.sh update im Terminal aus.")
    token = hashlib.sha256(("updater:" + settings.secret_key).encode()).hexdigest()
    req = urllib.request.Request(settings.updater_url.rstrip("/") + path, method=method, headers={"X-Updater-Token": token},
                                 data=b"" if method == "POST" else None)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error", "")
        except ValueError:
            msg = ""
        raise HTTPException(409 if e.code == 409 else 502, msg or f"Der Update-Dienst antwortet mit Fehler {e.code}.")
    except (urllib.error.URLError, OSError):
        raise HTTPException(503, "Der Update-Dienst ist nicht erreichbar. Führe einmalig ./install.sh update im Terminal aus.")


@router.get("/update")
def update_status(check: bool = False, admin: User = Depends(require_admin)):
    return _updater("GET", "/status" + ("?check=1" if check else ""))


@router.post("/update", status_code=202)
def start_update(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    r = _updater("POST", "/update")
    audit.record(db, admin.email, "update.start")
    return r


@router.get("/backups")
def list_backups(admin: User = Depends(require_admin)):
    return _updater("GET", "/backups")


@router.post("/backups", status_code=201)
def create_backup(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    r = _updater("POST", "/backups", timeout=300)
    audit.record(db, admin.email, "backup.create", r.get("name", ""))
    return r


# ---------- Protokoll und Zustand ----------

@router.get("/audit")
def audit_log(limit: int = 100, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.scalars(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(max(1, min(limit, 500)))).all()
    return [{"id": r.id, "at": r.at.isoformat() if r.at else None, "actor": r.actor, "action": r.action, "detail": r.detail} for r in rows]


def _db_size(db: Session) -> int | None:
    try:
        if db.bind.dialect.name == "postgresql":
            return int(db.scalar(text("select pg_database_size(current_database())")))
        if db.bind.dialect.name == "sqlite":
            path = db.bind.url.database
            return os.path.getsize(path) if path and os.path.exists(path) else None
    except Exception:
        return None
    return None


@router.get("/health")
def health(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    checks = []
    try:
        db.execute(text("select 1"))
        checks.append({"key": "db", "label": "Datenbank", "ok": True, "text": "erreichbar"})
    except Exception:
        checks.append({"key": "db", "label": "Datenbank", "ok": False, "text": "nicht erreichbar"})
    du = shutil.disk_usage("/")
    free_pct = du.free / du.total * 100
    checks.append({"key": "disk", "label": "Speicherplatz", "ok": free_pct >= 10, "text": f"{du.free / 1e9:.1f} GB frei von {du.total / 1e9:.0f} GB"})
    smtp = notify.smtp_configured()
    checks.append({"key": "mail", "label": "E-Mail-Versand", "ok": smtp, "text": "eingerichtet" if smtp else "nicht eingerichtet"})
    geo = geoip.status()
    geo_ok = all(v["present"] for v in geo.values())
    checks.append({"key": "geoip", "label": "Standort-Datenbanken (DB-IP)", "ok": geo_ok or not settings.geoip_enabled,
                   "text": "vorhanden" if geo_ok else ("ausgeschaltet" if not settings.geoip_enabled else "wird geladen oder fehlt")})
    try:
        _updater("GET", "/status", timeout=5)
        checks.append({"key": "updater", "label": "Update-Dienst", "ok": True, "text": "läuft"})
    except HTTPException:
        checks.append({"key": "updater", "label": "Update-Dienst", "ok": False, "text": "nicht erreichbar"})
    return {"checks": checks, "jobs": scheduler.status(), "users": db.scalar(select(func.count()).select_from(User)) or 0,
            "db_bytes": _db_size(db), "uptime_s": int(time.time() - STARTED), "python": platform.python_version()}


@router.post("/jobs/{name}", status_code=202)
def run_job(name: str, admin: User = Depends(require_admin)):
    if name not in scheduler.JOBS:
        raise HTTPException(404, "Unbekannte Aufgabe")
    if not scheduler.trigger(name):
        raise HTTPException(409, "Die Aufgabe läuft gerade.")
    return {"ok": True}
