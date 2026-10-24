"""Auswertung der Zugriffe: Verlauf, Ranglisten, Rohprotokoll und Details zu einer IP."""
import calendar
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import Integer, case, cast, distinct, func, select
from sqlalchemy.orm import Session

from .. import detect
from ..database import get_db
from ..models import AccessEvent, Incident, User
from ..netutil import classify
from ..security import current_user

router = APIRouter(prefix="/api/access", tags=["access"])

RANGES = {  # Zeitraum -> (Dauer, Abschnittsgröße in Sekunden)
    "1h": (timedelta(hours=1), 60),
    "24h": (timedelta(hours=24), 1800),
    "7d": (timedelta(days=7), 3 * 3600),
    "30d": (timedelta(days=30), 86400),
}


def epoch(db: Session, col):
    if db.bind.dialect.name == "postgresql":
        return cast(func.extract("epoch", col), Integer)
    return cast(func.strftime("%s", col), Integer)


def filters(rng: str, host: str | None, ip: str | None, country: str | None, status: str | None, q: str | None, scope: str | None):
    if rng not in RANGES:
        raise HTTPException(422, "Zeitraum: 1h, 24h, 7d oder 30d")
    since = datetime.utcnow() - RANGES[rng][0]
    conds = [AccessEvent.ts >= since]
    if host:
        conds.append(AccessEvent.host == host.lower())
    if ip:
        conds.append(AccessEvent.ip == ip)
    if country:
        conds.append(AccessEvent.country == (None if country == "--" else country.upper()))
    if status in ("2", "3", "4", "5"):
        lo = int(status) * 100
        conds += [AccessEvent.status >= lo, AccessEvent.status < lo + 100]
    elif status == "blocked":
        conds.append(AccessEvent.blocked.is_(True))
    if q:
        conds.append(AccessEvent.path.contains(q[:200]))
    if scope == "external":
        conds.append(AccessEvent.as_org.is_distinct_from("Heimnetz"))
    elif scope == "internal":
        conds.append(AccessEvent.as_org == "Heimnetz")
    return since, conds


def _event(e: AccessEvent) -> dict:
    return {"id": e.id, "ts": e.ts.isoformat(), "host": e.host, "method": e.method, "path": e.path, "status": e.status,
            "bytes": e.bytes, "ip": e.ip, "country": e.country, "as_org": e.as_org, "user_agent": e.user_agent,
            "referer": e.referer, "upstream": e.upstream, "blocked": bool(e.blocked)}


@router.get("/summary")
def summary(rng: str = Query("24h", alias="range"), host: str | None = None, ip: str | None = None, country: str | None = None,
            status: str | None = None, q: str | None = None, scope: str | None = None,
            user: User = Depends(current_user), db: Session = Depends(get_db)):
    since, conds = filters(rng, host, ip, country, status, q, scope)
    size = RANGES[rng][1]
    start = calendar.timegm(since.timetuple()) // size * size
    E = AccessEvent
    total, uniq, nbytes = db.execute(select(func.count(), func.count(distinct(E.ip)), func.sum(E.bytes)).where(*conds)).one()
    klass = cast(E.status // 100, Integer)
    bucket = (epoch(db, E.ts) // size).label("b")
    rows = db.execute(select(cast(bucket, Integer), klass, func.count()).where(*conds).group_by(cast(bucket, Integer), klass)).all()
    n = int(RANGES[rng][0].total_seconds() // size) + 1
    series = [{"t": datetime.utcfromtimestamp(start + i * size).isoformat(), "2": 0, "3": 0, "4": 0, "5": 0} for i in range(n)]
    for b, k, c in rows:
        i = int(b) - start // size
        if 0 <= i < n and str(k) in "2345":
            series[i][str(k)] += c

    def top(col, limit=10, extra=()):
        return db.execute(select(col, *extra, func.count().label("n")).where(*conds).group_by(col, *extra)
                          .order_by(func.count().desc()).limit(limit)).all()

    errors = db.scalar(select(func.count()).where(*conds, E.status >= 400)) or 0
    blocked = db.scalar(select(func.count()).where(*conds, E.blocked.is_(True))) or 0
    top_ips = []
    ip_rows = db.execute(select(E.ip, func.count().label("n"), func.max(E.country), func.max(E.as_org),
                                func.sum(case((E.status >= 400, 1), else_=0)))
                         .where(*conds).group_by(E.ip).order_by(func.count().desc()).limit(15)).all()
    find_block = detect.block_lookup(db)
    flagged = {r[0] for r in db.execute(select(Incident.ip).where(Incident.ip.in_([r[0] for r in ip_rows]), Incident.last_seen >= since))}
    for ipaddr, cnt, ctry, org, err in ip_rows:
        top_ips.append({"ip": ipaddr, "count": cnt, "country": ctry, "as_org": org, "errors": err or 0,
                        "scope": classify(ipaddr), "incident": ipaddr in flagged, "blocked": find_block(ipaddr) is not None})
    return {
        "range": rng, "bucket_s": size, "total": total or 0, "unique_ips": uniq or 0, "bytes": nbytes or 0,
        "errors": errors, "blocked": blocked, "series": series,
        "hosts": [{"host": h, "count": c} for h, c in top(E.host)],
        "ips": top_ips,
        "countries": [{"country": k, "count": c} for k, c in top(E.country, 12)],
        "statuses": [{"status": s, "count": c} for s, c in top(E.status, 12)],
        "paths": [{"path": p, "count": c} for p, c in top(E.path, 12)],
        "orgs": [{"as_org": o, "count": c} for o, c in top(E.as_org, 10)],
    }


@router.get("/events")
def events(rng: str = Query("24h", alias="range"), host: str | None = None, ip: str | None = None, country: str | None = None,
           status: str | None = None, q: str | None = None, scope: str | None = None,
           before_id: int | None = None, limit: int = Query(100, ge=1, le=500),
           user: User = Depends(current_user), db: Session = Depends(get_db)):
    _, conds = filters(rng, host, ip, country, status, q, scope)
    if before_id:
        conds.append(AccessEvent.id < before_id)
    rows = db.scalars(select(AccessEvent).where(*conds).order_by(AccessEvent.id.desc()).limit(limit)).all()
    return {"items": [_event(e) for e in rows], "next": rows[-1].id if len(rows) == limit else None}


@router.get("/hosts")
def hosts(user: User = Depends(current_user), db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(days=30)
    return sorted(h for (h,) in db.execute(select(distinct(AccessEvent.host)).where(AccessEvent.ts >= since)))


@router.get("/ip/{ip}")
def ip_detail(ip: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    from .. import geoip
    since = datetime.utcnow() - timedelta(days=30)
    E = AccessEvent
    conds = [E.ip == ip, E.ts >= since]
    total, first, last = db.execute(select(func.count(), func.min(E.ts), func.max(E.ts)).where(*conds)).one()
    country, asn, org = geoip.lookup(ip)
    hosts_ = db.execute(select(E.host, func.count()).where(*conds).group_by(E.host).order_by(func.count().desc()).limit(10)).all()
    statuses = db.execute(select(E.status, func.count()).where(*conds).group_by(E.status).order_by(func.count().desc()).limit(10)).all()
    agents = db.execute(select(E.user_agent, func.count()).where(*conds).group_by(E.user_agent).order_by(func.count().desc()).limit(5)).all()
    recent = db.scalars(select(E).where(*conds).order_by(E.id.desc()).limit(30)).all()
    incs = db.scalars(select(Incident).where(Incident.ip == ip).order_by(Incident.last_seen.desc()).limit(20)).all()
    block = detect.is_blocked(db, ip)
    return {
        "ip": ip, "scope": classify(ip), "country": country, "asn": asn, "as_org": org, "total": total or 0,
        "first": first.isoformat() if first else None, "last": last.isoformat() if last else None,
        "hosts": [{"host": h, "count": c} for h, c in hosts_],
        "statuses": [{"status": s, "count": c} for s, c in statuses],
        "user_agents": [{"user_agent": u, "count": c} for u, c in agents],
        "recent": [_event(e) for e in recent],
        "incidents": [{"id": i.id, "kind": i.kind, "severity": i.severity, "count": i.count, "last_seen": i.last_seen.isoformat()} for i in incs],
        "blocked": {"id": block.id, "cidr": block.cidr, "reason": block.reason, "expires_at": block.expires_at.isoformat() if block.expires_at else None} if block else None,
    }
