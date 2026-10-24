"""Agenten: Verwaltung in der Oberfläche und die Schnittstelle, über die Agenten Daten liefern."""
import hashlib
import json
import os
import secrets
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import accesslog, audit, detect, geoip, ratelimit
from ..config import settings
from ..database import get_db
from ..models import Agent, User
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
    }


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
    for a in db.scalars(select(Agent).order_by(Agent.id)):
        snap = _json(a.connections, {})
        est = []
        for c in snap.get("established", []):
            kind = classify(c.get("remote", ""))
            country, _, org = geoip.lookup(c.get("remote", "")) if kind == "public" else (None, None, None)
            blocked = find_block(c["remote"]) is not None if kind == "public" else False
            est.append({**c, "scope": kind, "country": country, "as_org": org, "blocked": blocked})
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
    blocks = sorted(b.cidr for b in detect.active_blocks(db))
    return {"blocklist": blocks, "blocklist_hash": hashlib.sha256("\n".join(blocks).encode()).hexdigest()[:16],
            "interval": 30}
