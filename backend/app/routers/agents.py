"""Agenten: Verwaltung in der Oberfläche und die Schnittstelle, über die Agenten Daten liefern."""
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import accesslog, audit, detect, fail2ban, geoip, hostwatch, ratelimit
from ..config import settings
from ..database import get_db
from ..models import Agent, User, WatchEvent
from ..netutil import classify
from ..security import current_user, require_admin

router = APIRouter(prefix="/api", tags=["agents"])

AGENT_DIR = os.environ.get("AGENT_DIR") or os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "agent"))
AGENT_FILES = {"install.sh": "text/x-shellscript", "nh-agent.py": "text/x-python"}
MAX_LINES = 5000


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _agent_from_token(authorization: str | None, db: Session) -> Agent:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Agent-Token fehlt")
    agent = db.scalar(select(Agent).where(Agent.token_hash == _hash(authorization[7:].strip())))
    if agent is None:
        raise HTTPException(401, "Agent-Token unbekannt. Wurde der Agent in NetworkHelper gelöscht?")
    return agent


def _json(text: str | None, default):
    try:
        return json.loads(text) if text else default
    except ValueError:
        return default


def agent_row(a: Agent) -> dict:
    now = datetime.utcnow()
    online = bool(a.last_seen and (now - a.last_seen).total_seconds() < 180)
    return {
        "id": a.id, "name": a.name, "hostname": a.hostname, "version": a.version, "online": online,
        "last_seen": a.last_seen.isoformat() if a.last_seen else None, "last_ip": a.last_ip,
        "created_at": a.created_at.isoformat() if a.created_at else None, "info": _json(a.info, {}),
        "log_files": _json(a.log_files, []), "enforce_blocks": bool(a.enforce_blocks), "block_status": a.block_status,
        "lines_total": a.lines_total or 0, "parse_errors": a.parse_errors or 0,
        "fail2ban": _f2b_summary(a),
    }


def _f2b_summary(a: Agent) -> dict:
    st = fail2ban.load(a)
    if not st.get("installed"):
        return {"installed": False}
    return {"installed": True, "running": bool(st.get("running")), "managed": bool(st.get("managed")), "error": st.get("error"),
            "banned": sum(j.get("banned", 0) for j in st.get("jails", [])),
            "jails": [{"name": j["name"], "label": fail2ban.JAIL_LABELS.get(j["name"], j["name"]), "banned": j.get("banned", 0),
                       "total_banned": j.get("total_banned", 0)} for j in st.get("jails", [])]}


def install_command(request: Request, token: str) -> str:
    base = settings.public_url.rstrip("/")
    # Für Agenten im Heimnetz ist die interne Adresse meist besser; die Oberfläche bietet beide an
    return f"curl -fsSL {base}/api/agent/files/install.sh | bash -s -- --server {base} --token {token}"


# ---------- Verwaltung ----------

class AgentIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)


@router.get("/agents")
def list_agents(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [agent_row(a) for a in db.scalars(select(Agent).order_by(Agent.id))]


@router.post("/agents", status_code=201)
def create_agent(data: AgentIn, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    token = "nh_" + secrets.token_urlsafe(32)
    agent = Agent(name=data.name.strip(), token_hash=_hash(token))
    db.add(agent)
    db.commit()
    audit.record(db, admin.email, "agent.create", agent.name)
    return {**agent_row(agent), "token": token, "command": install_command(request, token)}


@router.post("/agents/{agent_id}/token")
def renew_token(agent_id: int, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(404, "Agent nicht gefunden")
    token = "nh_" + secrets.token_urlsafe(32)
    agent.token_hash = _hash(token)
    db.commit()
    audit.record(db, admin.email, "agent.token", agent.name)
    return {**agent_row(agent), "token": token, "command": install_command(request, token)}


@router.put("/agents/{agent_id}")
def rename_agent(agent_id: int, data: AgentIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(404, "Agent nicht gefunden")
    agent.name = data.name.strip()
    db.commit()
    return agent_row(agent)


@router.delete("/agents/{agent_id}", status_code=204)
def delete_agent(agent_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(404, "Agent nicht gefunden")
    db.delete(agent)
    db.commit()
    audit.record(db, admin.email, "agent.delete", agent.name)


@router.get("/connections")
def connections(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Letzte Momentaufnahme jedes Agenten, ergänzt um Land und Netzbetreiber."""
    out = []
    find_block = detect.block_lookup(db)
    from .. import classify as cls, publicip
    agents_ = db.scalars(select(Agent).order_by(Agent.id)).all()
    remotes = sorted({c.get("remote", "") for a in agents_ for c in _json(a.connections, {}).get("established", []) if classify(c.get("remote", "")) == "public"})
    public_ip = publicip.info(db).get("ip")
    reasons = cls.classify_ips(db, datetime.utcnow() - timedelta(hours=24), public_ip, ips=remotes[:1000]) if remotes else {}
    for a in agents_:
        snap = _json(a.connections, {})
        est = []
        for c in snap.get("established", []):
            kind = classify(c.get("remote", ""))
            country, _, org = geoip.lookup(c.get("remote", "")) if kind == "public" else (None, None, None)
            blocked = find_block(c["remote"]) is not None if kind == "public" else False
            r = reasons.get(c.get("remote", ""))
            if r is None:
                r = cls.explain({"ip": c.get("remote", ""), "count": 0, "org": org}, public_ip)
                if kind == "public":
                    r = {**r, "why": r["why"] + [f"Keine Webzugriffe in den letzten 24 Stunden, nur diese Verbindung zu Port {c.get('lport')}"]}
            est.append({**c, "scope": kind, "country": country, "as_org": org, "blocked": blocked,
                        "reason": {k: r[k] for k in ("category", "label", "group", "why")}})
        est.sort(key=lambda c: (c["scope"] != "public", c.get("lport") or 0))
        out.append({**agent_row(a), "connections_at": a.connections_at.isoformat() if a.connections_at else None,
                    "established": est, "listening": sorted(snap.get("listening", []), key=lambda x: (x.get("port") or 0))})
    return out


# ---------- Schnittstelle für Agenten ----------

@router.get("/agent/files/{name}", response_class=PlainTextResponse)
def agent_file(name: str):
    if name not in AGENT_FILES:
        raise HTTPException(404, "Datei nicht gefunden")
    path = os.path.join(AGENT_DIR, name)
    if not os.path.exists(path):
        raise HTTPException(404, "Agent-Dateien fehlen im Container")
    with open(path, encoding="utf-8") as f:
        return PlainTextResponse(f.read(), media_type=AGENT_FILES[name])


class LogsIn(BaseModel):
    lines: list[str] = Field(default_factory=list, max_length=MAX_LINES)


@router.post("/agent/logs")
def agent_logs(data: LogsIn, request: Request, authorization: str | None = Header(None), db: Session = Depends(get_db)):
    agent = _agent_from_token(authorization, db)
    ok, bad = accesslog.ingest(db, data.lines, agent.id)
    agent.lines_total = (agent.lines_total or 0) + ok
    agent.parse_errors = (agent.parse_errors or 0) + bad
    agent.last_seen, agent.last_ip = datetime.utcnow(), ratelimit.client_ip(request)
    db.commit()
    return {"stored": ok, "unreadable": bad}


class StateIn(BaseModel):
    hostname: str | None = Field(default=None, max_length=120)
    version: str | None = Field(default=None, max_length=20)
    info: dict = Field(default_factory=dict)
    established: list[dict] = Field(default_factory=list, max_length=5000)
    listening: list[dict] = Field(default_factory=list, max_length=2000)
    log_files: list[dict] = Field(default_factory=list, max_length=200)
    enforce_blocks: bool = False
    block_status: str | None = Field(default=None, max_length=300)
    fail2ban: dict = Field(default_factory=dict)


@router.post("/agent/state")
def agent_state(data: StateIn, request: Request, authorization: str | None = Header(None), db: Session = Depends(get_db)):
    """Momentaufnahme des Servers. Die Antwort enthält die Sperrliste, die der Agent auf Wunsch umsetzt."""
    agent = _agent_from_token(authorization, db)
    now = datetime.utcnow()
    agent.hostname, agent.version = data.hostname, data.version
    agent.info = json.dumps(data.info)[:20000]
    agent.connections = json.dumps({"established": data.established, "listening": data.listening})
    agent.connections_at = now
    agent.log_files = json.dumps(data.log_files)[:20000]
    agent.enforce_blocks, agent.block_status = data.enforce_blocks, data.block_status
    agent.last_seen, agent.last_ip = now, ratelimit.client_ip(request)
    db.commit()
    hostwatch.check_ports(db, agent, data.listening)
    if data.fail2ban:
        fail2ban.ingest(db, agent, data.fail2ban)
    from .. import geoblock
    blocks = sorted(b.cidr for b in detect.active_blocks(db))
    http_hash, snippet = geoblock.current(db)
    digest = hashlib.sha256(("\n".join(blocks) + "|" + (http_hash or "")).encode()).hexdigest()[:16]
    return {"blocklist": blocks, "blocklist_hash": digest, "http_conf_hash": http_hash, "server_snippet": snippet if http_hash else "",
            "interval": 30, "agent_version": agent_version(), "own_ips": fail2ban.own_ips(db),
            "f2b_unban": fail2ban.take_unban(db, agent.id)}


@router.get("/agent/own-ips")
def agent_own_ips(authorization: str | None = Header(None), db: Session = Depends(get_db)):
    """Eigene öffentliche IPs, die fail2ban beim Einrichten gleich ausnehmen soll."""
    _agent_from_token(authorization, db)
    return {"own_ips": fail2ban.own_ips(db)}


def agent_version() -> str | None:
    """Version der mitgelieferten Agent-Datei; neuere Agenten aktualisieren sich darauf."""
    try:
        with open(os.path.join(AGENT_DIR, "nh-agent.py"), encoding="utf-8") as f:
            for line in f:
                if line.startswith("VERSION = "):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        return None
    return None


@router.get("/agent/http-conf", response_class=PlainTextResponse)
def agent_http_conf(authorization: str | None = Header(None), db: Session = Depends(get_db)):
    _agent_from_token(authorization, db)
    from .. import geoblock
    return PlainTextResponse(geoblock.http_conf(db), media_type="text/plain")


class WatchIn(BaseModel):
    logins: list[dict] = Field(default_factory=list, max_length=500)
    failures: dict = Field(default_factory=dict)
    users: list[dict] = Field(default_factory=list, max_length=500)
    files: dict = Field(default_factory=dict)
    proxmox: bool = False


@router.post("/agent/watch")
def agent_watch(data: WatchIn, authorization: str | None = Header(None), db: Session = Depends(get_db)):
    agent = _agent_from_token(authorization, db)
    if len(data.files) > 1000 or len(data.failures) > 1000:
        raise HTTPException(413, "Zu viele Einträge")
    return hostwatch.ingest(db, agent, data.model_dump())


# ---------- Wachsamkeit in der Oberfläche ----------

@router.get("/agents/{agent_id}/watch")
def agent_watch_view(agent_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(404, "Agent nicht gefunden")
    return hostwatch.summary(db, agent)


class AckIn(BaseModel):
    acknowledged: bool = True


@router.put("/watch/events/{event_id}")
def ack_watch_event(event_id: int, data: AckIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    ev = db.get(WatchEvent, event_id)
    if ev is None:
        raise HTTPException(404, "Nicht gefunden")
    ev.acknowledged = data.acknowledged
    db.commit()
    audit.record(db, admin.email, "watch.ack", ev.title[:290])
    return hostwatch.event_out(ev)


@router.post("/agents/{agent_id}/watch/ack-all")
def ack_all_watch(agent_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    n = 0
    for ev in db.scalars(select(WatchEvent).where(WatchEvent.agent_id == agent_id, WatchEvent.acknowledged.is_(False))):
        ev.acknowledged = True
        n += 1
    db.commit()
    audit.record(db, admin.email, "watch.ack_all", f"Agent {agent_id}: {n}")
    return {"acknowledged": n}
