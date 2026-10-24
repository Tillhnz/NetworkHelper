"""DNS bei Porkbun: Records, DynDNS und Abgleich mit dem Proxy Manager."""
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, dns, npm, porkbun, publicip, scheduler, state
from ..config import settings
from ..database import get_db
from ..models import DynRecord, User
from ..security import current_user, require_admin

router = APIRouter(prefix="/api/dns", tags=["dns"])

NAME_RE = re.compile(r"^(\*|[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?)*$")


def _err(e: Exception) -> HTTPException:
    return HTTPException(502, str(e))


def _check_domain(domain: str) -> str:
    domain = domain.lower()
    try:
        allowed = porkbun.managed_domains()
    except porkbun.PorkbunError as e:
        raise _err(e)
    if domain not in allowed:
        raise HTTPException(404, "Diese Domain wird nicht verwaltet (Administration → DNS)")
    return domain


@router.get("/status")
def dns_status(user: User = Depends(current_user), db: Session = Depends(get_db)):
    domains, error = [], None
    if porkbun.configured():
        try:
            domains = porkbun.managed_domains()
        except porkbun.PorkbunError as e:
            error = str(e)
    dyn = db.scalars(select(DynRecord).order_by(DynRecord.domain, DynRecord.name)).all()
    return {
        "configured": porkbun.configured(), "npm_configured": npm.configured(), "domains": domains, "error": error,
        "public_ip": publicip.info(db), "dyndns_enabled": settings.dyndns_enabled, "dyndns_interval_min": settings.dyndns_interval_min,
        "dyndns_last": state.get(db, "dyndns_last"), "new_record_type": settings.dns_new_record_type,
        "npm_auto_dns": settings.npm_auto_dns, "npm_sync": state.get(db, "npm_sync"),
        "dyn_records": [{"id": d.id, "domain": d.domain, "name": d.name, "type": d.type, "enabled": d.enabled, "last_ip": d.last_ip,
                         "last_update": d.last_update.isoformat() if d.last_update else None, "last_error": d.last_error} for d in dyn],
    }


@router.get("/records/{domain}")
def records(domain: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    domain = _check_domain(domain)
    try:
        recs = porkbun.records(domain)
    except porkbun.PorkbunError as e:
        raise _err(e)
    dyn = {(d.name, d.type): d.enabled for d in db.scalars(select(DynRecord).where(DynRecord.domain == domain))}
    for r in recs:
        r["dyn"] = dyn.get((r["name"], r["type"]), False)
    recs.sort(key=lambda r: (r["type"] not in ("A", "AAAA", "CNAME", "ALIAS"), r["name"], r["type"]))
    return {"domain": domain, "records": recs}


class RecordIn(BaseModel):
    name: str = Field(default="", max_length=200)
    type: str = Field(max_length=6)
    content: str = Field(default="", max_length=1000)
    ttl: int = Field(default=600, ge=60, le=86400)
    dyn: bool = False


def _clean(data: RecordIn, db: Session) -> tuple[str, str, str]:
    name = data.name.strip().lower().rstrip(".")
    rtype = data.type.upper()
    if rtype not in porkbun.RECORD_TYPES:
        raise HTTPException(422, "Unbekannter Record-Typ")
    if name and not NAME_RE.match(name):
        raise HTTPException(422, "Ungültige Subdomain (erlaubt: Buchstaben, Ziffern, Bindestrich, Punkt, *)")
    content = data.content.strip()
    if rtype == "A" and (data.dyn or not content or content == "@ip"):
        content = publicip.current(db) or ""
        if not content:
            raise HTTPException(422, "Die öffentliche IP ist unbekannt, bitte die Adresse selbst eintragen.")
    if not content:
        raise HTTPException(422, "Inhalt fehlt")
    return name, rtype, content


@router.post("/records/{domain}", status_code=201)
def create_record(domain: str, data: RecordIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    domain = _check_domain(domain)
    name, rtype, content = _clean(data, db)
    try:
        rid = porkbun.create(domain, name, rtype, content, data.ttl, notes="NetworkHelper")
    except porkbun.PorkbunError as e:
        raise _err(e)
    if data.dyn and rtype in ("A", "AAAA"):
        row = dns.ensure_dyn(db, domain, name, rtype)
        row.last_ip = content
        db.commit()
    audit.record(db, admin.email, "dns.create", f"{rtype} {name + '.' if name else ''}{domain} -> {content}"[:290])
    return {"id": rid}


@router.put("/records/{domain}/{record_id}")
def edit_record(domain: str, record_id: str, data: RecordIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    domain = _check_domain(domain)
    name, rtype, content = _clean(data, db)
    try:
        porkbun.edit(domain, record_id, name, rtype, content, data.ttl)
    except porkbun.PorkbunError as e:
        raise _err(e)
    if rtype in ("A", "AAAA"):
        dns.ensure_dyn(db, domain, name, rtype, enabled=data.dyn)
    audit.record(db, admin.email, "dns.edit", f"{rtype} {name + '.' if name else ''}{domain} -> {content}"[:290])
    return {"ok": True}


@router.delete("/records/{domain}/{record_id}", status_code=204)
def delete_record(domain: str, record_id: str, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    domain = _check_domain(domain)
    try:
        recs = porkbun.records(domain)
        rec = next((r for r in recs if r["id"] == record_id), None)
        porkbun.delete(domain, record_id)
    except porkbun.PorkbunError as e:
        raise _err(e)
    if rec:
        row = db.scalar(select(DynRecord).where(DynRecord.domain == domain, DynRecord.name == rec["name"], DynRecord.type == rec["type"]))
        if row:
            db.delete(row)
            db.commit()
        audit.record(db, admin.email, "dns.delete", f"{rec['type']} {rec['fqdn']}"[:290])


class DynIn(BaseModel):
    domain: str
    name: str = ""
    type: str = "A"
    enabled: bool


@router.put("/dyn")
def set_dyn(data: DynIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    domain = _check_domain(data.domain)
    if data.type not in ("A", "AAAA"):
        raise HTTPException(422, "DynDNS geht nur für A- und AAAA-Records")
    if data.type == "AAAA":
        raise HTTPException(422, "DynDNS für IPv6 wird noch nicht unterstützt")
    if data.enabled:
        dns.ensure_dyn(db, domain, data.name, data.type)
        scheduler.trigger("dyndns")
    else:
        row = db.scalar(select(DynRecord).where(DynRecord.domain == domain, DynRecord.name == data.name, DynRecord.type == data.type))
        if row:
            db.delete(row)
            db.commit()
    return {"ok": True}


@router.post("/dyndns/run")
def run_dyndns(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if not porkbun.configured():
        raise HTTPException(422, "Porkbun ist nicht eingerichtet")
    return dns.run_dyndns(db, force=True)


@router.get("/npm")
def npm_overview(user: User = Depends(current_user), db: Session = Depends(get_db)):
    try:
        return dns.npm_overview(db)
    except (npm.NpmError, porkbun.PorkbunError) as e:
        raise _err(e)


class FqdnIn(BaseModel):
    fqdns: list[str] = Field(min_length=1, max_length=200)


@router.post("/npm/create")
def npm_create(data: FqdnIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        domains = porkbun.managed_domains()
    except porkbun.PorkbunError as e:
        raise _err(e)
    done, errors = [], []
    for fqdn in data.fqdns:
        split = dns.split_fqdn(fqdn, domains)
        if not split:
            errors.append(f"{fqdn}: keine verwaltete Domain")
            continue
        try:
            rec = dns.create_for_host(db, *split)
            done.append({"fqdn": fqdn, **rec})
        except porkbun.PorkbunError as e:
            errors.append(f"{fqdn}: {e}")
    if done:
        audit.record(db, admin.email, "dns.npm", ", ".join(d["fqdn"] for d in done)[:290])
    return {"created": done, "errors": errors}


# ---------- Domain-Schutz (SPF, DMARC, Null-MX, CAA) ----------

@router.get("/protection")
def protection(refresh: bool = False, user: User = Depends(current_user), db: Session = Depends(get_db)):
    from .. import domainguard
    data = state.get(db, "domainguard")
    if (refresh or not data) and porkbun.configured():
        data = domainguard.run(db)
    return {"configured": porkbun.configured(), **(data or {"domains": [], "checked": None})}


@router.post("/protection/{domain}/{key}", status_code=201)
def protection_fix(domain: str, key: str, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    from .. import domainguard
    domain = domain.lower()
    if domain not in [d.lower() for d in porkbun.managed_domains()]:
        raise HTTPException(404, "Diese Domain verwaltet NetworkHelper nicht")
    current = domainguard.analyze(domain, porkbun.records(domain))
    check = next((c for c in current["checks"] if c.get("fix") == key and not c["ok"]), None)
    if check is None:
        raise HTTPException(409, "Für diese Domain ist dieser Eintrag nicht (mehr) nötig")
    try:
        domainguard.apply_fix(domain, key)
    except porkbun.PorkbunError as e:
        raise HTTPException(502, str(e))
    audit.record(db, admin.email, "dns.protect", f"{domain}: {key}")
    return domainguard.run(db)
