"""AdGuard Home: Übersicht, Schutz pausieren, Namen freigeben, DNS-Umschreibungen."""
import re

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import adguard, audit
from ..database import SessionLocal, get_db
from ..models import User
from ..security import current_user, require_admin

router = APIRouter(prefix="/api/adguard", tags=["adguard"])
NAME_RE = re.compile(r"^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


def _call(fn, *args):
    try:
        return fn(*args)
    except adguard.AdGuardError as e:
        raise HTTPException(502, str(e))


def _overview():
    with SessionLocal() as db:
        return adguard.overview(db)


@router.get("")
async def overview(user: User = Depends(current_user)):
    return await run_in_threadpool(_overview)


class ProtectionIn(BaseModel):
    enabled: bool
    minutes: int = Field(0, ge=0, le=24 * 60)


@router.post("/protection")
def protection(data: ProtectionIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    _call(adguard.set_protection, data.enabled, data.minutes)
    audit.record(db, admin.email, "adguard.protection", "an" if data.enabled else f"pausiert {data.minutes or 'dauerhaft'} Min.")
    return adguard.status()


class NameIn(BaseModel):
    domain: str = Field(..., max_length=253)


def _name(value: str) -> str:
    v = value.strip().lower().rstrip(".")
    if not NAME_RE.match(v):
        raise HTTPException(422, "Kein gültiger Name")
    return v


@router.post("/allow")
def allow(data: NameIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    name = _name(data.domain).lstrip("*.")
    rule = _call(adguard.allow_domain, name)
    audit.record(db, admin.email, "adguard.allow", name)
    return {"rule": rule}


class RewriteIn(BaseModel):
    domain: str = Field(..., max_length=253)
    answer: str = Field(..., max_length=253)


@router.post("/rewrites", status_code=201)
def add_rewrite(data: RewriteIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    domain, answer = _name(data.domain), data.answer.strip()
    if not answer or " " in answer:
        raise HTTPException(422, "Bitte eine IP-Adresse oder einen Namen als Ziel angeben")
    _call(adguard.add_rewrite, domain, answer)
    audit.record(db, admin.email, "adguard.rewrite.add", f"{domain} → {answer}")
    return {"domain": domain, "answer": answer}


@router.post("/rewrites/delete")
def delete_rewrite(data: RewriteIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    _call(adguard.delete_rewrite, data.domain, data.answer)
    audit.record(db, admin.email, "adguard.rewrite.delete", data.domain)
    return {"ok": True}
