"""Fehlersuche für einen Hostnamen auf Knopfdruck."""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import diagnose, npm
from ..database import SessionLocal, get_db
from ..models import Monitor, SiteCheck, User
from ..security import current_user

router = APIRouter(prefix="/api/diagnose", tags=["diagnose"])


class DiagnoseIn(BaseModel):
    target: str = Field(min_length=3, max_length=300)


def _run(target: str) -> dict:
    with SessionLocal() as db:
        return diagnose.run(db, target)


@router.post("")
async def run_diagnosis(data: DiagnoseIn, user: User = Depends(current_user)):
    try:
        return await run_in_threadpool(_run, data.target)
    except ValueError as e:
        raise HTTPException(422, str(e))


@router.get("/hosts")
def known_hosts(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Bekannte Namen als Vorschläge: Seitenprüfung, Erreichbarkeit und (falls verbunden) Proxy Manager."""
    names = set(db.scalars(select(SiteCheck.host)))
    names |= {diagnose.host_of(u) for u in db.scalars(select(Monitor.url))}
    if npm.configured():
        try:
            names |= {d for h in npm.raw_proxy_hosts() for d in h["domains"] if not d.startswith("*")}
        except npm.NpmError:
            pass
    return sorted(n for n in names if n and "." in n)
