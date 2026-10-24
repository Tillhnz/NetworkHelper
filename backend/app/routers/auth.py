import json
import re
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit, ratelimit
from ..config import settings
from ..database import get_db
from ..models import Invite, User
from ..security import create_token, current_user, hash_password, is_admin, verify_password

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
            "onboarding_done": bool(u.onboarding_done), "tour_done": bool(u.tour_done), "hints_hidden": _hints(u)}


class OnboardingIn(BaseModel):
    onboarding_done: bool | None = None
    tour_done: bool | None = None
    hide_hint: str | None = Field(default=None, max_length=40)
    show_hints: bool = False  # alle ausgeblendeten Hinweise wieder anzeigen


def token_out(user: User) -> dict:
    return {"access_token": create_token(user), "token_type": "bearer"}


_DUMMY_HASH = hash_password("dummy-password-for-timing")


@router.get("/config")
def public_config():
    return {"allow_registration": settings.allow_registration}


@router.post("/auth/register", status_code=201)
def register(data: RegisterIn, request: Request, db: Session = Depends(get_db)):
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
    return token_out(user)


@router.post("/auth/login")
def login(data: Credentials, request: Request, db: Session = Depends(get_db)):
    ip = ratelimit.client_ip(request)
    ratelimit.check_login(data.email, ip)
    user = db.scalar(select(User).where(User.email == data.email))
    ok = verify_password(data.password, user.password_hash if user else _DUMMY_HASH)
    if not user or not ok:
        ratelimit.record_failure(data.email, ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "E-Mail oder Passwort falsch")
    ratelimit.record_success(data.email)
    if user.active is False:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Dieses Konto ist gesperrt.")
    return token_out(user)


def check_password(user: User, password: str, request: Request) -> None:
    ip = ratelimit.client_ip(request)
    ratelimit.check_login(user.email, ip)
    if not verify_password(password, user.password_hash):
        ratelimit.record_failure(user.email, ip)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Passwort falsch")


@router.put("/auth/password")
def change_password(data: PasswordChangeIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    check_password(user, data.current_password, request)
    user.password_hash = hash_password(data.new_password)
    user.token_version = (user.token_version or 0) + 1
    db.commit()
    return token_out(user)


@router.post("/auth/logout-all")
def logout_all(user: User = Depends(current_user), db: Session = Depends(get_db)):
    user.token_version = (user.token_version or 0) + 1
    db.commit()
    return token_out(user)


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
