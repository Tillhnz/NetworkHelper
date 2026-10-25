import json
import re
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit, ratelimit, totp
from ..config import settings
from ..database import get_db
from ..models import Invite, User
from ..security import create_challenge, create_token, current_user, hash_password, is_admin, read_challenge, verify_password

router = APIRouter(prefix="/api", tags=["auth"])

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")


class Credentials(BaseModel):
    email: str = Field(max_length=255)
    password: str = Field(min_length=1, max_length=200)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_RE.match(v):
            raise ValueError("Keine gültige E-Mail-Adresse")
        return v


class RegisterIn(Credentials):
    password: str = Field(min_length=8, max_length=200)
    invite: str | None = Field(default=None, max_length=32)


class PasswordChangeIn(BaseModel):
    current_password: str = Field(max_length=200)
    new_password: str = Field(min_length=8, max_length=200)


class PasswordConfirmIn(BaseModel):
    password: str = Field(max_length=200)


class AlertPrefIn(BaseModel):
    alert_email: bool


def _hints(u: User) -> list[str]:
    try:
        return json.loads(u.hints_hidden) if u.hints_hidden else []
    except ValueError:
        return []


def user_out(u: User) -> dict:
    admin = u.role == "admin"
    return {"id": u.id, "email": u.email, "role": "admin" if admin else "user", "is_admin": admin,
            "alert_email": u.alert_email if u.alert_email is not None else admin,
            "onboarding_done": bool(u.onboarding_done), "tour_done": bool(u.tour_done), "hints_hidden": _hints(u),
            "two_factor": bool(u.totp_enabled), "must_setup_2fa": bool(settings.two_factor_required and not u.totp_enabled)}


class OnboardingIn(BaseModel):
    onboarding_done: bool | None = None
    tour_done: bool | None = None
    hide_hint: str | None = Field(default=None, max_length=40)
    unhide_hint: str | None = Field(default=None, max_length=40)
    show_hints: bool = False  # alle ausgeblendeten Hinweise wieder anzeigen


from ..security import SESSION_COOKIE as COOKIE  # noqa: E402


def token_out(user: User, response: Response | None = None, request: Request | None = None) -> dict:
    """Neue Sitzung. Der Browser bekommt sie als HttpOnly-Cookie (für Skripte unlesbar); das Token im JSON ist für API-Clients."""
    token = create_token(user)
    if response is not None:
        secure = bool(request and (request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").lower() == "https"))
        samesite = settings.cookie_samesite.lower() if settings.cookie_samesite.lower() in ("strict", "lax", "none") else "strict"
        if samesite == "none" and not secure:
            samesite = "lax"  # Browser verwerfen SameSite=None ohne HTTPS
        response.set_cookie(COOKIE, token, max_age=settings.token_expire_days * 86400, httponly=True, samesite=samesite,
                            secure=secure or samesite == "none", path="/api")
    return {"access_token": token, "token_type": "bearer"}


_DUMMY_HASH = hash_password("dummy-password-for-timing")


@router.get("/config")
def public_config():
    return {"allow_registration": settings.allow_registration}


@router.post("/auth/register", status_code=201)
def register(data: RegisterIn, request: Request, response: Response, db: Session = Depends(get_db)):
    ratelimit.check_register(ratelimit.client_ip(request))
    first_user = db.scalar(select(User.id).limit(1)) is None
    invite = None
    if not first_user and not settings.allow_registration:
        code = (data.invite or "").strip().upper()
        invite = db.scalar(select(Invite).where(Invite.code == code, Invite.used_at.is_(None))) if code else None
        if invite is None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Registrierung nur mit gültigem Einladungscode")
    if db.scalar(select(User).where(User.email == data.email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "E-Mail bereits vergeben")
    user = User(email=data.email, password_hash=hash_password(data.password), token_version=0,
                role="admin" if first_user else "user", active=True)
    db.add(user)
    if invite is not None:
        invite.used_by_email, invite.used_at = data.email, datetime.utcnow()
    db.commit()
    if invite is not None:
        audit.record(db, data.email, "user.register", f"Einladung {invite.code}")
    return token_out(user, response, request)


@router.post("/auth/login")
def login(data: Credentials, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = ratelimit.client_ip(request)
    ratelimit.check_login(data.email, ip)
    user = db.scalar(select(User).where(User.email == data.email))
    ok = verify_password(data.password, user.password_hash if user else _DUMMY_HASH)
    if not user or not ok:
        ratelimit.record_failure(data.email, ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "E-Mail oder Passwort falsch")
    if user.active is False:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Dieses Konto ist gesperrt.")
    if user.totp_enabled:
        # Passwort stimmt, jetzt fehlt noch der Code aus der App. Fehlversuche zählen weiter, bis der Code stimmt.
        return {"two_factor": True, "challenge": create_challenge(user)}
    ratelimit.record_success(data.email)
    return token_out(user, response, request)


class SecondFactorIn(BaseModel):
    challenge: str = Field(max_length=1000)
    code: str = Field(min_length=6, max_length=20)


def _check_second_factor(user: User, code: str, db: Session) -> str | None:
    """Prüft Code aus der App oder Wiederherstellungscode. Gibt 'app' bzw. 'recovery' zurück oder None."""
    secret = totp.decrypt(user.totp_secret)
    digits = "".join(ch for ch in code if ch.isdigit())
    if secret and len(digits) == totp.DIGITS and len(code.strip()) <= 7:
        step = totp.verify(secret, code, user.totp_last_step)
        if step is not None:
            user.totp_last_step = step
            return "app"
        return None
    rest = totp.use_recovery(user.recovery_codes, code)
    if rest is not None:
        user.recovery_codes = rest
        return "recovery"
    return None


@router.post("/auth/login/2fa")
def login_second_factor(data: SecondFactorIn, request: Request, response: Response, db: Session = Depends(get_db)):
    user = read_challenge(data.challenge, db)
    if user is None or not user.totp_enabled:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Die Anmeldung ist abgelaufen. Bitte gib dein Passwort erneut ein.")
    ip = ratelimit.client_ip(request)
    ratelimit.check_login(user.email, ip)
    kind = _check_second_factor(user, data.code, db)
    if kind is None:
        ratelimit.record_failure(user.email, ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Der Code stimmt nicht. Achte darauf, den aktuellen Code aus der App zu nehmen.")
    ratelimit.record_success(user.email)
    db.commit()
    if kind == "recovery":
        left = totp.recovery_left(user.recovery_codes)
        audit.record(db, user.email, "2fa.recovery_used", f"noch {left} Codes")
        from .. import notify
        notify.raise_alert(db, "warn", "account", f"Anmeldung mit Wiederherstellungscode: {user.email}",
                           f"Für das Konto {user.email} wurde ein Wiederherstellungscode benutzt. Übrig: {left}.\n"
                           "Warst du das nicht, ändere sofort das Passwort und richte die Zwei-Faktor-Anmeldung neu ein.",
                           dedupe_key=f"recovery:{user.id}:{left}", dedupe_hours=1)
    return token_out(user, response, request)


def check_password(user: User, password: str, request: Request) -> None:
    ip = ratelimit.client_ip(request)
    ratelimit.check_login(user.email, ip)
    if not verify_password(password, user.password_hash):
        ratelimit.record_failure(user.email, ip)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Passwort falsch")


@router.put("/auth/password")
def change_password(data: PasswordChangeIn, request: Request, response: Response, user: User = Depends(current_user), db: Session = Depends(get_db)):
    check_password(user, data.current_password, request)
    user.password_hash = hash_password(data.new_password)
    user.token_version = (user.token_version or 0) + 1
    db.commit()
    return token_out(user, response, request)


@router.post("/auth/logout-all")
def logout_all(request: Request, response: Response, user: User = Depends(current_user), db: Session = Depends(get_db)):
    user.token_version = (user.token_version or 0) + 1
    db.commit()
    return token_out(user, response, request)


@router.post("/auth/logout", status_code=204)
def logout(request: Request, response: Response):
    token_out_attrs = {"path": "/api", "httponly": True}
    if settings.cookie_samesite.lower() == "none":
        token_out_attrs.update(secure=True, samesite="none")
    response.delete_cookie(COOKIE, **token_out_attrs)


@router.post("/auth/session")
def session_from_token(request: Request, response: Response, user: User = Depends(current_user)):
    """Übernimmt eine ältere, im Browser gespeicherte Anmeldung in das sichere Cookie."""
    return token_out(user, response, request)


@router.get("/me")
def me(user: User = Depends(current_user)):
    return user_out(user)


@router.put("/me/alerts")
def set_alerts(data: AlertPrefIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    user.alert_email = data.alert_email
    db.commit()
    return user_out(user)


@router.put("/me/onboarding")
def set_onboarding(data: OnboardingIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if data.onboarding_done is not None:
        user.onboarding_done = data.onboarding_done
    if data.tour_done is not None:
        user.tour_done = data.tour_done
    hints = [] if data.show_hints else _hints(user)
    if data.hide_hint and data.hide_hint not in hints:
        hints.append(data.hide_hint)
    if data.unhide_hint:
        hints = [h for h in hints if h != data.unhide_hint]
    user.hints_hidden = json.dumps(hints[-100:])
    db.commit()
    return user_out(user)


@router.post("/me/delete", status_code=204)
def delete_account(data: PasswordConfirmIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    check_password(user, data.password, request)
    admins = db.scalar(select(func.count()).select_from(User).where(User.role == "admin")) or 0
    others = (db.scalar(select(func.count()).select_from(User)) or 0) > 1
    if is_admin(db, user) and admins <= 1 and others:
        raise HTTPException(status.HTTP_409_CONFLICT, "Du bist der letzte Administrator. Ernenne zuerst jemand anderen.")
    db.delete(user)
    db.commit()


# ---------- Zwei-Faktor-Anmeldung einrichten ----------

class TwoFactorSetupIn(BaseModel):
    password: str = Field(max_length=200)


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=20)


class TwoFactorConfirmIn(BaseModel):
    password: str = Field(max_length=200)
    code: str = Field(min_length=6, max_length=20)


def two_factor_out(u: User) -> dict:
    return {"enabled": bool(u.totp_enabled), "enabled_at": u.totp_enabled_at.isoformat() if u.totp_enabled_at else None,
            "recovery_left": totp.recovery_left(u.recovery_codes) if u.totp_enabled else 0,
            "required": settings.two_factor_required}


@router.get("/me/2fa")
def two_factor_status(user: User = Depends(current_user)):
    return two_factor_out(user)


@router.post("/me/2fa/setup")
def two_factor_setup(data: TwoFactorSetupIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Die Zwei-Faktor-Anmeldung ist schon eingerichtet.")
    check_password(user, data.password, request)
    secret = totp.new_secret()
    user.totp_pending = totp.encrypt(secret)
    db.commit()
    uri = totp.uri(secret, user.email)
    return {"secret": " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)), "uri": uri, "qr_svg": totp.qr_svg(uri)}


@router.post("/me/2fa/enable")
def two_factor_enable(data: CodeIn, request: Request, response: Response, user: User = Depends(current_user), db: Session = Depends(get_db)):
    secret = totp.decrypt(user.totp_pending)
    if not secret:
        raise HTTPException(status.HTTP_409_CONFLICT, "Bitte starte die Einrichtung neu.")
    step = totp.verify(secret, data.code)
    if step is None:
        raise HTTPException(422, "Der Code stimmt nicht. Prüfe, ob die Uhrzeit am Handy automatisch gestellt wird, und nimm den aktuellen Code.")
    codes, hashed = totp.new_recovery_codes()
    user.totp_secret, user.totp_pending, user.totp_enabled = totp.encrypt(secret), None, True
    user.totp_last_step, user.totp_enabled_at, user.recovery_codes = step, datetime.utcnow(), hashed
    user.token_version = (user.token_version or 0) + 1  # andere Geräte müssen sich neu (mit Code) anmelden
    db.commit()
    audit.record(db, user.email, "2fa.enable", "")
    return {**token_out(user, response, request), "recovery_codes": codes, "status": two_factor_out(user)}


@router.post("/me/2fa/disable")
def two_factor_disable(data: TwoFactorConfirmIn, request: Request, response: Response, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Die Zwei-Faktor-Anmeldung ist nicht eingerichtet.")
    if settings.two_factor_required:
        raise HTTPException(status.HTTP_409_CONFLICT, "Die Zwei-Faktor-Anmeldung ist für alle Konten vorgeschrieben.")
    check_password(user, data.password, request)
    if _check_second_factor(user, data.code, db) is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Der Code stimmt nicht.")
    user.totp_enabled, user.totp_secret, user.totp_pending, user.recovery_codes, user.totp_enabled_at = False, None, None, None, None
    user.token_version = (user.token_version or 0) + 1
    db.commit()
    audit.record(db, user.email, "2fa.disable", "")
    return {**token_out(user, response, request), "status": two_factor_out(user)}


@router.post("/me/2fa/recovery")
def two_factor_new_recovery(data: TwoFactorConfirmIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Die Zwei-Faktor-Anmeldung ist nicht eingerichtet.")
    check_password(user, data.password, request)
    if _check_second_factor(user, data.code, db) is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Der Code stimmt nicht.")
    codes, hashed = totp.new_recovery_codes()
    user.recovery_codes = hashed
    db.commit()
    audit.record(db, user.email, "2fa.recovery_new", "")
    return {"recovery_codes": codes, "status": two_factor_out(user)}
