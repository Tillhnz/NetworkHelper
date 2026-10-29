"""Erreichbarkeit: Monitore anlegen, ändern, prüfen und ihren Verlauf zeigen."""
import json
import re
import threading

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import uptime
from ..database import SessionLocal, get_db
from ..models import Monitor, User
from ..security import current_user, require_admin

router = APIRouter(prefix="/api/monitors", tags=["monitors"])


class MonitorIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    url: str = Field(min_length=8, max_length=500)
    expect: str = Field(default="200-399", max_length=40)
    keyword: str | None = Field(default=None, max_length=120)
    verify_tls: bool = True
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^https?://[^\s/]+", v):
            raise ValueError("Adresse mit http:// oder https:// erwartet")
        return v

    @field_validator("expect")
    @classmethod
    def _expect(cls, v: str) -> str:
        v = v.strip() or "200-399"
        if not re.fullmatch(r"\d{3}(-\d{3})?([,\s]+\d{3}(-\d{3})?)*", v):
            raise ValueError("Statuscodes wie 200-399 oder 200,401")
        return v


def _row(db: Session, m: Monitor, with_history: bool = True) -> dict:
    out = {"id": m.id, "name": m.name, "url": m.url, "expect": m.expect, "keyword": m.keyword, "verify_tls": m.verify_tls,
           "enabled": m.enabled, "source": m.source, "state": m.state if m.enabled else "paused",
           "last_check": m.last_check.isoformat() if m.last_check else None, "latency_ms": m.last_latency_ms,
           "last_status": m.last_status, "last_error": m.last_error, "changed_at": m.changed_at.isoformat() if m.changed_at else None,
           "diagnosis": json.loads(m.diagnosis) if m.diagnosis and m.state == "down" else None,
           "uptime_24h": uptime.uptime_pct(db, m.id, 1), "uptime_7d": uptime.uptime_pct(db, m.id, 7), "uptime_30d": uptime.uptime_pct(db, m.id, 30)}
    if with_history:
        out["history"] = uptime.history(db, m.id, 24, 48)
    return out


@router.get("")
def list_monitors(user: User = Depends(current_user), db: Session = Depends(get_db)):
    mons = db.scalars(select(Monitor).order_by(Monitor.name)).all()
    order = {"down": 0, "unknown": 1, "up": 2}
    rows = [_row(db, m) for m in mons]
    rows.sort(key=lambda r: (order.get(r["state"], 3), r["name"].lower()))
    return rows


@router.get("/{monitor_id}")
def get_monitor(monitor_id: int, hours: int = 24, user: User = Depends(current_user), db: Session = Depends(get_db)):
    m = db.get(Monitor, monitor_id)
    if m is None:
        raise HTTPException(404, "Monitor nicht gefunden")
    hours = max(1, min(hours, 24 * 30))
    return {**_row(db, m, False), "history": uptime.history(db, m.id, hours, 60)}


def _check_soon(ids: list[int]) -> None:
    def run():
        with SessionLocal() as db:
            uptime.run_due(db, force_ids=ids)
    threading.Thread(target=run, daemon=True).start()


@router.post("", status_code=201)
def create_monitor(data: MonitorIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    m = Monitor(**data.model_dump(), source="manual")
    db.add(m)
    db.commit()
    _check_soon([m.id])
    return _row(db, m)


@router.put("/{monitor_id}")
def update_monitor(monitor_id: int, data: MonitorIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    m = db.get(Monitor, monitor_id)
    if m is None:
        raise HTTPException(404, "Monitor nicht gefunden")
    for k, v in data.model_dump().items():
        if m.source == "npm" and k == "url":
            continue  # die Adresse kommt aus dem Proxy Manager
        setattr(m, k, v)
    db.commit()
    return _row(db, m)


@router.delete("/{monitor_id}", status_code=204)
def delete_monitor(monitor_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    m = db.get(Monitor, monitor_id)
    if m is None:
        raise HTTPException(404, "Monitor nicht gefunden")
    if m.source == "npm":
        raise HTTPException(409, "Dieser Monitor kommt aus dem Proxy Manager. Pausiere ihn oder schalte unter Administration den automatischen Abgleich aus.")
    db.delete(m)
    db.commit()


@router.post("/check", status_code=202)
def check_all(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    ids = list(db.scalars(select(Monitor.id).where(Monitor.enabled.is_(True))))
    _check_soon(ids)
    return {"ok": True, "count": len(ids)}
