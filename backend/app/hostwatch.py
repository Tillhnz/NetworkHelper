"""Wachsamkeit auf den Servern: wertet aus, was die Agenten über Anmeldungen, Benutzer, wichtige Dateien und
lauschende Ports melden. Beim ersten Bericht wird nur der Ausgangsstand gemerkt; danach wird jede Änderung gemeldet.

Die Vergleichsbasis rückt nach jeder Meldung auf den aktuellen Stand vor; die Ereignisse bleiben, bis jemand sie mit
„War ich“ bestätigt. So gibt es keine Dauer-Meldungen, aber auch nichts geht verloren.
"""
from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import notify
from .models import Agent, WatchEvent, WatchState
from .netutil import classify

# Dateien, deren Änderung fast immer etwas mit Zugang zu tun hat
CRITICAL_FILES = ("authorized_keys", "/etc/sudoers", "/etc/ld.so.preload", "/etc/shadow", "/etc/pam.d/", "/etc/passwd")
FAILS_ALERT = 10  # fehlgeschlagene Anmeldungen einer Adresse innerhalb eines Berichts
EPHEMERAL_PORT = 32768  # höhere Ports wechseln oft (z. B. Rückkanäle) und werden nicht als neuer Dienst gemeldet


def _load(text: str | None, default):
    try:
        return json.loads(text) if text else default
    except ValueError:
        return default


def _state(db: Session, agent: Agent) -> WatchState:
    st = db.get(WatchState, agent.id)
    if st is None:
        st = WatchState(agent_id=agent.id)
        db.add(st)
    return st


def _event(db: Session, agent: Agent, kind: str, severity: str, title: str, detail: str = "", ts: datetime | None = None,
           alert: bool = False, dedupe: str | None = None) -> WatchEvent:
    ev = WatchEvent(agent_id=agent.id, kind=kind, severity=severity, title=title[:200], detail=detail[:4000] or None,
                    ts=ts or datetime.utcnow(), acknowledged=severity == "info")
    db.add(ev)
    if alert:
        notify.raise_alert(db, severity, "host", f"{agent.name}: {title}", detail + "\n\nWarst du das? Dann unter Verbindungen auf „War ich“ klicken.",
                           dedupe_key=dedupe or f"host:{agent.id}:{kind}:{title}", dedupe_hours=6, commit=False)
    return ev


def _file_severity(path: str) -> str:
    return "crit" if any(k in path for k in CRITICAL_FILES) else "warn"


def ingest(db: Session, agent: Agent, data: dict) -> dict:
    st = _state(db, agent)
    first = st.updated_at is None
    counts = {"events": 0}

    # Anmeldungen
    known = set(_load(st.known_logins, []))
    for lg in (data.get("logins") or [])[:500]:
        user, ip, service = str(lg.get("user") or "?")[:60], lg.get("ip"), lg.get("service") or "ssh"
        ts = datetime.utcfromtimestamp(lg["ts"]) if isinstance(lg.get("ts"), (int, float)) else None
        scope = classify(ip) if ip else "unknown"
        key = f"{service}|{user}|{ip or '-'}"
        where = f" von {ip}" if ip else ""
        new_pair = key not in known
        known.add(key)
        if scope == "public":
            sev, alert = ("crit" if new_pair else "warn"), True
            title = f"{'Neue ' if new_pair else ''}Anmeldung aus dem Internet: {user}{where}"
        elif new_pair and not first:
            sev, alert, title = "warn", True, f"Erste Anmeldung als {user}{where} ({service})"
        else:
            sev, alert, title = "info", False, f"Anmeldung als {user}{where} ({service})"
        _event(db, agent, "login", sev, title, f"Dienst: {service}, Methode: {lg.get('method') or '?'}", ts=ts, alert=alert,
               dedupe=f"host-login:{agent.id}:{key}")
        counts["events"] += 1
    st.known_logins = json.dumps(sorted(known)[-500:])

    # Viele Fehlversuche
    for ip, n in sorted((data.get("failures") or {}).items(), key=lambda x: -x[1])[:50]:
        try:
            n = int(n)
        except (TypeError, ValueError):
            continue
        if n >= FAILS_ALERT:
            public = classify(ip) == "public"
            _event(db, agent, "login_fail", "warn", f"{n} fehlgeschlagene Anmeldungen von {ip}",
                   "Jemand probiert Passwörter aus." + (" Die Adresse kommt aus dem Internet: Ist SSH etwa per Portfreigabe erreichbar? "
                                                       "Dann besser schließen und nur per VPN anmelden." if public else ""),
                   alert=public, dedupe=f"host-fail:{agent.id}:{ip}")
            counts["events"] += 1

    # Benutzer
    users = {u["name"]: u for u in (data.get("users") or []) if isinstance(u, dict) and u.get("name")}
    old_users = {u["name"]: u for u in _load(st.users, [])}
    if not first:
        for name, u in users.items():
            if name not in old_users:
                _event(db, agent, "user_new", "crit", f"Neues Benutzerkonto: {name}", f"uid {u.get('uid')}, Shell {u.get('shell')}"
                       + (", mit Administratorrechten" if u.get("admin") else ""), alert=True)
                counts["events"] += 1
            elif u.get("admin") and not old_users[name].get("admin"):
                _event(db, agent, "admin_new", "crit", f"{name} hat jetzt Administratorrechte", "Mitglied in sudo/wheel oder uid 0", alert=True)
                counts["events"] += 1
        for name in old_users:
            if name not in users:
                _event(db, agent, "user_gone", "warn", f"Benutzerkonto entfernt oder gesperrt: {name}")
                counts["events"] += 1
    st.users = json.dumps(list(users.values()))

    # Dateien
    files = {str(k)[:300]: str(v)[:64] for k, v in (data.get("files") or {}).items()}
    old_files = _load(st.files, {})
    if not first and old_files:
        changed = [p for p in files if p in old_files and files[p] != old_files[p]]
        added = [p for p in files if p not in old_files]
        gone = [p for p in old_files if p not in files]
        for kind, paths, verb in (("file_changed", changed, "geändert"), ("file_new", added, "neu"), ("file_gone", gone, "gelöscht")):
            if not paths:
                continue
            sev = "crit" if any(_file_severity(p) == "crit" for p in paths) and kind != "file_gone" else "warn"
            title = f"{len(paths)} wichtige Systemdatei{'en' if len(paths) > 1 else ''} {verb}" if len(paths) > 1 else f"Systemdatei {verb}: {paths[0]}"
            _event(db, agent, kind, sev, title, "\n".join(paths[:50]), alert=True, dedupe=f"host-file:{agent.id}:{kind}:{','.join(sorted(paths))[:200]}")
            counts["events"] += 1
    st.files = json.dumps(files)
    st.proxmox = bool(data.get("proxmox"))
    st.updated_at = datetime.utcnow()
    db.commit()
    return counts


def check_ports(db: Session, agent: Agent, listening: list[dict]) -> None:
    """Neue lauschende Ports (Dienste) gegenüber dem bekannten Stand melden."""
    st = _state(db, agent)
    now_ports = {f"{p.get('proto')}/{p.get('port')}": (p.get("process") or "") for p in listening
                 if isinstance(p.get("port"), int) and p["port"] < EPHEMERAL_PORT}
    old = _load(st.ports, None)
    if old is not None:
        for key, proc in now_ports.items():
            if key not in old:
                _event(db, agent, "port_new", "warn", f"Neuer Dienst lauscht auf {key}{f' ({proc})' if proc else ''}",
                       "Ein Programm nimmt jetzt Verbindungen auf diesem Port an. Neu installiert? Sonst prüfen.", alert=True,
                       dedupe=f"host-port:{agent.id}:{key}")
        for key in old:
            if key not in now_ports:
                _event(db, agent, "port_gone", "info", f"Dienst auf {key} beendet")
    st.ports = json.dumps(now_ports)
    db.commit()


def event_out(e: WatchEvent) -> dict:
    return {"id": e.id, "agent_id": e.agent_id, "ts": e.ts.isoformat(), "kind": e.kind, "severity": e.severity, "title": e.title,
            "detail": e.detail, "acknowledged": e.acknowledged}


def summary(db: Session, agent: Agent) -> dict:
    st = db.get(WatchState, agent.id)
    open_events = db.scalars(select(WatchEvent).where(WatchEvent.agent_id == agent.id, WatchEvent.acknowledged.is_(False))
                             .order_by(WatchEvent.ts.desc()).limit(50)).all()
    logins = db.scalars(select(WatchEvent).where(WatchEvent.agent_id == agent.id, WatchEvent.kind == "login")
                        .order_by(WatchEvent.ts.desc()).limit(10)).all()
    return {"active": st is not None and st.updated_at is not None, "updated_at": st.updated_at.isoformat() if st and st.updated_at else None,
            "users": _load(st.users, []) if st else [], "files": len(_load(st.files, {})) if st else 0,
            "proxmox": bool(st and st.proxmox), "open": [event_out(e) for e in open_events], "logins": [event_out(e) for e in logins]}
