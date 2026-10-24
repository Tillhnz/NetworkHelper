"""Sicherheit: offene Ports, Zertifikate und Header, Vorfälle, Sperrliste."""
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .. import audit, detect, portscan, scheduler, state
from ..database import get_db
from ..models import ExpectedPort, Incident, PortFinding, SiteCheck, User
from ..security import current_user, require_admin
from ..server_settings import HOST_RE

router = APIRouter(prefix="/api/security", tags=["security"])


# ---------- Ports ----------

@router.get("/ports")
def ports(user: User = Depends(current_user), db: Session = Depends(get_db)):
    ok = portscan.expected(db)
    rows = db.scalars(select(PortFinding).order_by(PortFinding.open.desc(), PortFinding.port)).all()
    items = [{
        "id": f.id, "target": f.target, "port": f.port, "source": f.source, "service": f.service or portscan.SERVICES.get(f.port),
        "banner": f.banner, "open": f.open, "first_seen": f.first_seen.isoformat(), "last_seen": f.last_seen.isoformat(),
        "closed_at": f.closed_at.isoformat() if f.closed_at else None, "expected": f.port in ok, "risky": f.port in portscan.RISKY,
    } for f in rows]
    return {"items": items, "expected": sorted(ok), "last": state.get(db, "portscan_last"),
            "running": scheduler.JOBS["portscan"].running, "default_ports": len(portscan.ports_to_scan())}


class ExpectIn(BaseModel):
    port: int = Field(ge=1, le=65535)
    expected: bool
    note: str | None = Field(default=None, max_length=120)


@router.put("/ports/expected")
def set_expected(data: ExpectIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    current = portscan.expected(db)
    if not db.scalar(select(func.count()).select_from(ExpectedPort)):
        for p in current:  # Startwerte aus der Einstellung übernehmen, damit sie nicht verloren gehen
            db.add(ExpectedPort(port=p))
        db.flush()
    row = db.get(ExpectedPort, data.port)
    if data.expected and row is None:
        db.add(ExpectedPort(port=data.port, note=data.note))
    elif not data.expected and row is not None:
        db.delete(row)
    db.commit()
    audit.record(db, admin.email, "port.expected" if data.expected else "port.unexpected", str(data.port))
    return {"expected": sorted(portscan.expected(db))}


@router.post("/ports/scan", status_code=202)
def scan_now(admin: User = Depends(require_admin)):
    if not scheduler.trigger("portscan"):
        raise HTTPException(409, "Der Scan läuft bereits.")
    return {"ok": True}


@router.delete("/ports/closed", status_code=204)
def clear_closed(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    db.execute(delete(PortFinding).where(PortFinding.open.is_(False)))
    db.commit()


# ---------- Zertifikate und Header ----------

def _site(s: SiteCheck) -> dict:
    days = (s.cert_expires - datetime.utcnow()).days if s.cert_expires else None
    return {"host": s.host, "checked_at": s.checked_at.isoformat() if s.checked_at else None, "grade": s.grade, "score": s.score,
            "cert_expires": s.cert_expires.isoformat() if s.cert_expires else None, "cert_days": days, "cert_issuer": s.cert_issuer,
            "cert_valid": s.cert_valid, "tls_version": s.tls_version, "https_redirect": s.https_redirect, "status": s.status,
            "checks": json.loads(s.checks) if s.checks else [], "error": s.error, "source": s.source, "enabled": s.enabled}


@router.get("/sites")
def sites(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(SiteCheck).order_by(SiteCheck.host)).all()
    return {"items": [_site(s) for s in rows], "running": scheduler.JOBS["sitecheck"].running}


class SiteIn(BaseModel):
    host: str = Field(min_length=3, max_length=253)


@router.post("/sites", status_code=201)
def add_site(data: SiteIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    host = data.host.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    if not HOST_RE.match(host) or "." not in host:
        raise HTTPException(422, "Bitte einen Hostnamen wie cloud.example.de eingeben")
    if db.get(SiteCheck, host):
        raise HTTPException(409, "Dieser Hostname wird schon geprüft")
    db.add(SiteCheck(host=host, source="manual", enabled=True))
    db.commit()
    from .. import sitecheck
    import threading
    threading.Thread(target=lambda: _check_one(host, sitecheck), daemon=True).start()
    return {"host": host}


def _check_one(host: str, module) -> None:
    from ..database import SessionLocal
    with SessionLocal() as db:
        module.run(db, [host])


@router.delete("/sites/{host}", status_code=204)
def remove_site(host: str, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    row = db.get(SiteCheck, host)
    if row is None:
        raise HTTPException(404, "Nicht gefunden")
    if row.source == "npm":
        row.enabled = not row.enabled  # Hosts aus dem Proxy Manager kämen sonst sofort zurück: nur pausieren
    else:
        db.delete(row)
    db.commit()


@router.post("/sites/check", status_code=202)
def check_sites(admin: User = Depends(require_admin)):
    if not scheduler.trigger("sitecheck"):
        raise HTTPException(409, "Die Prüfung läuft bereits.")
    return {"ok": True}


# ---------- Vorfälle ----------

def _incident(i: Incident) -> dict:
    return {"id": i.id, "ip": i.ip, "kind": i.kind, "kind_text": detect.KIND_TEXT.get(i.kind, i.kind), "severity": i.severity,
            "first_seen": i.first_seen.isoformat(), "last_seen": i.last_seen.isoformat(), "count": i.count,
            "hosts": [h for h in (i.hosts or "").split(",") if h], "sample": json.loads(i.sample) if i.sample else [],
            "country": i.country, "as_org": i.as_org, "acknowledged": i.acknowledged}


@router.get("/incidents")
def incidents(open_only: bool = False, limit: int = Query(200, le=1000), user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = select(Incident).order_by(Incident.last_seen.desc()).limit(limit)
    if open_only:
        q = q.where(Incident.acknowledged.is_(False))
    rows = db.scalars(q).all()
    find_block = detect.block_lookup(db)
    return [{**_incident(i), "blocked": find_block(i.ip) is not None} for i in rows]


@router.post("/incidents/ack-all", status_code=204)
def ack_all(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    for i in db.scalars(select(Incident).where(Incident.acknowledged.is_(False))):
        i.acknowledged = True
    db.commit()


@router.put("/incidents/{incident_id}/ack")
def ack(incident_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "Vorfall nicht gefunden")
    inc.acknowledged = not inc.acknowledged
    db.commit()
    return _incident(inc)


# ---------- Sperrliste ----------

def _block(b) -> dict:
    return {"id": b.id, "cidr": b.cidr, "reason": b.reason, "created_at": b.created_at.isoformat(), "created_by": b.created_by,
            "expires_at": b.expires_at.isoformat() if b.expires_at else None, "auto": b.auto}


@router.get("/blocks")
def blocks(user: User = Depends(current_user), db: Session = Depends(get_db)):
    from ..models import Agent
    enforcing = [a.name for a in db.scalars(select(Agent).where(Agent.enforce_blocks.is_(True)))]
    return {"items": [_block(b) for b in detect.active_blocks(db)], "enforcing_agents": enforcing}


class BlockIn(BaseModel):
    cidr: str = Field(min_length=2, max_length=49)
    reason: str | None = Field(default=None, max_length=200)
    hours: float | None = Field(default=None, gt=0, le=24 * 365)


@router.post("/blocks", status_code=201)
def add_block(data: BlockIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    from ..netutil import classify
    try:
        cidr = data.cidr.strip()
        if "/" not in cidr and classify(cidr) in ("private", "loopback"):
            raise ValueError("Adressen aus dem Heimnetz werden nicht gesperrt, sonst sperrst du dich womöglich selbst aus.")
        row = detect.add_block(db, cidr, data.reason or "", data.hours, by=admin.email)
    except ValueError as e:
        raise HTTPException(422, str(e))
    audit.record(db, admin.email, "block.add", row.cidr)
    return _block(row)


@router.delete("/blocks/{block_id}", status_code=204)
def remove_block(block_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    from ..accesslog import block_cache
    from ..models import BlockEntry
    row = db.get(BlockEntry, block_id)
    if row is None:
        raise HTTPException(404, "Sperre nicht gefunden")
    db.delete(row)
    db.commit()
    block_cache.invalidate()
    audit.record(db, admin.email, "block.remove", row.cidr)
