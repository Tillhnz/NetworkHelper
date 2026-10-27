"""fail2ban auf den Servern: Status und Sperren aus den Agenten-Berichten, Entsperren und Teilen von Sperren.

fail2ban sperrt direkt in der Firewall eines Servers, innerhalb von Sekunden und auch, wenn NetworkHelper gerade
nicht läuft. NetworkHelper ergänzt das: Er zeigt alle Sperren an einem Ort, übernimmt auf Wunsch neue Sperren in
seine eigene Sperrliste (dann gelten sie auf allen Servern und im Proxy Manager) und schickt Entsperr-Wünsche an
die Agenten.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import detect, geoip, publicip, state
from .config import settings
from .models import Agent, BlockEntry
from .netutil import classify

SYNC_JAIL = "networkhelper"
JAIL_LABELS = {
    "sshd": "SSH-Anmeldung",
    "networkhelper-npm-auth": "Anmeldungen an deinen Webseiten",
    "networkhelper-npm-scan": "Suche nach Schwachstellen",
    "networkhelper-proxmox": "Proxmox-Anmeldung",
    SYNC_JAIL: "Sperrliste von NetworkHelper",
}
JAIL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,60}$")
SHARE_HOURS = 24


def _ip(value) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def clean(status: dict) -> dict:
    """Bericht des Agenten prüfen und begrenzen (er kommt von außen)."""
    if not isinstance(status, dict) or not status.get("installed"):
        return {"installed": False}
    jails = []
    for j in (status.get("jails") or [])[:30]:
        if not isinstance(j, dict) or not JAIL_RE.match(str(j.get("name", ""))):
            continue
        ips = [x for x in (_ip(i) for i in (j.get("ips") or [])[:500]) if x]
        jails.append({"name": j["name"], "failed": int(j.get("failed") or 0), "total_failed": int(j.get("total_failed") or 0),
                      "banned": int(j.get("banned") or 0), "total_banned": int(j.get("total_banned") or 0), "ips": ips})
    return {"installed": True, "running": bool(status.get("running")), "managed": bool(status.get("managed")),
            "version": str(status.get("version") or "")[:20] or None, "error": str(status.get("error") or "")[:200] or None,
            "jails": jails}


def load(agent: Agent) -> dict:
    try:
        return json.loads(agent.fail2ban) if agent.fail2ban else {}
    except ValueError:
        return {}


def own_ips(db: Session) -> list[str]:
    """Eigene öffentliche IPs (aktuell und in der letzten Woche), die fail2ban nie sperren soll."""
    week = datetime.utcnow() - timedelta(days=7)
    return sorted({ip for ip, _start, end in publicip.own_periods(db) if end is None or end >= week})


def ingest(db: Session, agent: Agent, status: dict) -> None:
    new = clean(status)
    old = load(agent)
    new["updated_at"] = datetime.utcnow().isoformat()
    agent.fail2ban = json.dumps(new)
    if not (settings.fail2ban_share and new.get("running")):
        db.commit()
        return
    before = {(j["name"], ip) for j in old.get("jails", []) for ip in j.get("ips", [])}
    periods = publicip.own_periods(db)
    for j in new["jails"]:
        if j["name"] == SYNC_JAIL:
            continue  # stammt von NetworkHelper selbst
        for ip in j["ips"]:
            if (j["name"], ip) in before or classify(ip) != "public" or publicip.is_own(periods, ip):
                continue
            if detect.is_blocked(db, ip):
                continue
            detect.add_block(db, ip, f"fail2ban auf {agent.name}: {JAIL_LABELS.get(j['name'], j['name'])}",
                             hours=SHARE_HOURS, by=f"fail2ban ({agent.name})", auto=True)
    db.commit()


def take_unban(db: Session, agent_id: int) -> list[dict]:
    key = f"f2b_unban:{agent_id}"
    items = state.get(db, key) or []
    if items:
        state.put(db, key, [])
    return items


def request_unban(db: Session, ip: str) -> dict:
    """Entsperrt eine Adresse überall: in allen fail2ban-Jails aller Agenten und in der Sperrliste von NetworkHelper."""
    ip = _ip(ip)
    if not ip:
        raise ValueError("Keine gültige IP-Adresse")
    queued = 0
    for a in db.scalars(select(Agent)):
        jails = [j["name"] for j in load(a).get("jails", []) if ip in j.get("ips", [])]
        if not jails:
            continue
        key = f"f2b_unban:{a.id}"
        items = state.get(db, key) or []
        items += [{"jail": j, "ip": ip} for j in jails]
        state.put(db, key, items[-200:], commit=False)
        queued += len(jails)
    removed = 0
    for b in db.scalars(select(BlockEntry).where(BlockEntry.cidr == ip)):
        db.delete(b)
        removed += 1
    db.commit()
    if removed:
        from .accesslog import block_cache
        block_cache.invalidate()
    return {"ip": ip, "jails": queued, "blocks_removed": removed}


def overview(db: Session) -> dict:
    agents = []
    for a in db.scalars(select(Agent).order_by(Agent.id)):
        st = load(a)
        if not a.last_seen:
            continue
        jails = []
        for j in st.get("jails", []):
            ips = []
            for ip in j.get("ips", [])[:200]:
                country, _, org = geoip.lookup(ip)
                ips.append({"ip": ip, "country": country, "as_org": org})
            jails.append({**{k: j[k] for k in ("name", "failed", "total_failed", "banned", "total_banned")},
                          "label": JAIL_LABELS.get(j["name"], j["name"]), "ips": ips})
        agents.append({"id": a.id, "name": a.name, "version": a.version, "installed": bool(st.get("installed")),
                       "running": bool(st.get("running")), "managed": bool(st.get("managed")), "error": st.get("error"),
                       "fail2ban_version": st.get("version"), "updated_at": st.get("updated_at"), "jails": jails})
    return {"agents": agents, "share": settings.fail2ban_share}


def ssh_exposed(db: Session) -> list[tuple[str, int]]:
    """Server, auf denen fail2ban SSH-Angreifer aus dem Internet sperrt: Dann ist SSH von außen erreichbar."""
    out = []
    for a in db.scalars(select(Agent)):
        for j in load(a).get("jails", []):
            if j["name"] in ("sshd", "networkhelper-proxmox") and any(classify(ip) == "public" for ip in j.get("ips", [])):
                out.append((f"{a.name} ({JAIL_LABELS[j['name']]})", j.get("banned", 0)))
    return out
