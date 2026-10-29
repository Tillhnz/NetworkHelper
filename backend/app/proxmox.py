"""Proxmox VE: Überblick über Host, Container und VMs, nur lesend.

NetworkHelper fragt die Proxmox-API mit einem API-Token ab, das nur die Rolle „PVEAuditor“ hat. Damit kann er alles
ansehen, aber nichts starten, stoppen, ändern oder löschen, auch nicht, wenn jemand NetworkHelper übernimmt.
Das Zertifikat von Proxmox ist meist selbst signiert. Deshalb merkt sich NetworkHelper beim ersten Verbinden dessen
Fingerabdruck und verbindet sich danach nur noch mit genau diesem Server.
"""
from __future__ import annotations

import hashlib
import socket
import ssl
from datetime import datetime, timedelta
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import notify, state
from .config import settings
from .models import Agent

BACKUP_WARN_DAYS = 8
SNAPSHOT_KEY = "proxmox_snapshot"


class ProxmoxError(RuntimeError):
    pass


def configured() -> bool:
    return bool(settings.proxmox_url and settings.proxmox_token_id and settings.proxmox_token_secret)


def _hostport() -> tuple[str, int]:
    u = urlparse(settings.proxmox_url)
    return u.hostname or "", u.port or 8006


def fingerprint() -> str:
    """SHA-256-Fingerabdruck des Zertifikats, das der Server gerade zeigt (AA:BB:…)."""
    host, port = _hostport()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=8) as sock, ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    except OSError as e:
        raise ProxmoxError(f"Proxmox nicht erreichbar ({e.__class__.__name__}). Stimmt die Adresse mit Port 8006?")
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def _norm(fp: str) -> str:
    return fp.replace(":", "").replace(" ", "").upper()


def _check_fp() -> None:
    want = settings.proxmox_fingerprint
    if not want:
        raise ProxmoxError("Der Fingerabdruck des Proxmox-Zertifikats ist noch nicht bestätigt (Administration → Proxmox → „Verbindung testen“).")
    got = fingerprint()
    if _norm(got) != _norm(want):
        raise ProxmoxError(f"Das Zertifikat von Proxmox hat sich geändert (jetzt {got[:23]}…). Hast du es selbst erneuert, "
                           "bestätige es unter Administration → Proxmox neu. Sonst könnte jemand die Verbindung umleiten.")


def _get(client: httpx.Client, path: str):
    try:
        r = client.get(settings.proxmox_url.rstrip("/") + "/api2/json" + path)
    except httpx.HTTPError as e:
        raise ProxmoxError(f"Proxmox nicht erreichbar ({e.__class__.__name__})")
    if r.status_code == 401:
        raise ProxmoxError("Proxmox lehnt das API-Token ab. Stimmen Token-ID (z. B. networkhelper@pve!monitor) und Geheimnis?")
    if r.status_code == 403:
        return None  # fehlendes Recht: Bereich überspringen
    if r.status_code >= 400:
        raise ProxmoxError(f"Proxmox meldet Fehler {r.status_code} bei {path}")
    return r.json().get("data")


def _client() -> httpx.Client:
    _check_fp()
    return httpx.Client(verify=False, timeout=20, headers={
        "Authorization": f"PVEAPIToken={settings.proxmox_token_id}={settings.proxmox_token_secret}"})


def test(save_fp: bool = False) -> dict:
    """Für den Knopf „Verbindung testen“: liefert Fingerabdruck, Version und ob das Token zu viel darf."""
    if not configured():
        raise ProxmoxError("Bitte Adresse, Token-ID und Geheimnis eintragen.")
    fp = fingerprint()
    headers = {"Authorization": f"PVEAPIToken={settings.proxmox_token_id}={settings.proxmox_token_secret}"}
    with httpx.Client(verify=False, timeout=20, headers=headers) as c:
        version = _get(c, "/version") or {}
        perms = _get(c, "/access/permissions") or {}
    root = perms.get("/") or {}
    dangerous = sorted(p for p, v in root.items() if v and (p.endswith(".Modify") or p.endswith(".Allocate") or p in (
        "VM.PowerMgmt", "VM.Console", "Sys.Console", "Sys.PowerMgmt", "Permissions.Modify", "VM.Config.Disk", "Datastore.Allocate")))
    return {"fingerprint": fp, "pinned": bool(settings.proxmox_fingerprint) and _norm(fp) == _norm(settings.proxmox_fingerprint),
            "version": version.get("version"), "too_many_rights": dangerous[:8]}


# ---------- Abfragen ----------

def _guest_checks(g: dict, cfg: dict, backup_at: datetime | None, now: datetime) -> list[dict]:
    out = []

    def add(level, text, fix):
        out.append({"level": level, "text": text, "fix": fix})
    if g["type"] == "lxc":
        privileged = str(cfg.get("unprivileged", "0")) != "1"
        feats = str(cfg.get("features") or "")
        if privileged:
            add("crit" if "nesting=1" in feats else "warn",
                "Privilegierter Container" + (" mit Nesting" if "nesting=1" in feats else "")
                + ": root im Container ist fast root auf dem Proxmox-Host.",
                "Container per Sicherung und Wiederherstellung mit Haken „Unprivilegiert“ neu anlegen.")
        for k, v in cfg.items():
            if k.startswith("mp") and isinstance(v, str) and v.split(",")[0].startswith("/") and privileged:
                add("warn", f"Ordner vom Host eingebunden ({v.split(',')[0]}) in einem privilegierten Container.",
                    "In unprivilegierten Containern ist das harmloser.")
                break
    else:
        if str(cfg.get("agent", "0")).split(",")[0] not in ("1", "enabled=1"):
            add("info", "QEMU-Gastagent aus: Proxmox sieht IP-Adressen nicht und Sicherungen sind nicht dateisystemkonsistent.",
                "In der VM qemu-guest-agent installieren und unter Optionen „QEMU Guest Agent“ einschalten.")
    if g["template"]:
        return out
    if backup_at is None:
        add("warn", "Keine Sicherung gefunden.", "Rechenzentrum → Backup → Hinzufügen: tägliche Sicherung für diesen Gast.")
    elif now - backup_at > timedelta(days=BACKUP_WARN_DAYS):
        add("warn", f"Letzte Sicherung vor {(now - backup_at).days} Tagen.", "Läuft der Backup-Job? Ist der Speicher voll?")
    return out


def collect() -> dict:
    now = datetime.utcnow()
    with _client() as c:
        version = (_get(c, "/version") or {}).get("version")
        nodes = _get(c, "/nodes") or []
        resources = _get(c, "/cluster/resources?type=vm") or []
        users = _get(c, "/access/users?full=1") or []
        tfa = _get(c, "/access/tfa")
        fw = _get(c, "/cluster/firewall/options") or {}
        jobs = _get(c, "/cluster/backup") or []
        backups: dict[int, datetime] = {}
        node_info = []
        for n in nodes:
            name = n.get("node")
            if n.get("status") != "online":
                node_info.append({"name": name, "online": False})
                continue
            updates = _get(c, f"/nodes/{name}/apt/update") or []
            security = [u for u in updates if "security" in str(u.get("Origin", "")).lower() or "-security" in str(u.get("Section", ""))]
            status = _get(c, f"/nodes/{name}/status") or {}
            for s in _get(c, f"/nodes/{name}/storage?content=backup&enabled=1") or []:
                for item in _get(c, f"/nodes/{name}/storage/{s['storage']}/content?content=backup") or []:
                    vmid, ct = item.get("vmid"), item.get("ctime")
                    if vmid and ct:
                        t = datetime.utcfromtimestamp(int(ct))
                        if vmid not in backups or t > backups[vmid]:
                            backups[int(vmid)] = t
            node_info.append({"name": name, "online": True, "uptime": n.get("uptime"), "cpu": n.get("cpu"),
                              "mem": n.get("mem"), "maxmem": n.get("maxmem"),
                              "pve": (status.get("pveversion") or "").split("/")[1] if "/" in (status.get("pveversion") or "") else version,
                              "kernel": (status.get("current-kernel") or {}).get("release") or status.get("kversion"),
                              "updates": len(updates), "security_updates": len(security),
                              "security_list": sorted({u.get("Package") for u in security if u.get("Package")})[:15]})
        guests = []
        for r in resources:
            if r.get("type") not in ("lxc", "qemu"):
                continue
            g = {"vmid": int(r["vmid"]), "name": r.get("name") or f"#{r['vmid']}", "type": r["type"], "node": r.get("node"),
                 "status": r.get("status"), "uptime": r.get("uptime"), "template": bool(r.get("template")),
                 "maxmem": r.get("maxmem"), "mem": r.get("mem"), "cpu": r.get("cpu")}
            cfg = _get(c, f"/nodes/{g['node']}/{g['type']}/{g['vmid']}/config") or {}
            g["onboot"] = str(cfg.get("onboot", "0")) == "1"
            g["unprivileged"] = str(cfg.get("unprivileged", "0")) == "1" if g["type"] == "lxc" else None
            g["firewall"] = any("firewall=1" in str(v) for k, v in cfg.items() if k.startswith("net"))
            g["backup_at"] = backups.get(g["vmid"]).isoformat() if backups.get(g["vmid"]) else None
            g["checks"] = _guest_checks(g, cfg, backups.get(g["vmid"]), now)
            guests.append(g)
    guests.sort(key=lambda g: g["vmid"])
    tfa_users = {t.get("userid") for t in (tfa or []) if t.get("entries")} if tfa is not None else None
    acct = []
    for u in users:
        uid = u.get("userid")
        if not uid or not u.get("enable", 1):
            continue
        has_tfa = (uid in tfa_users) if tfa_users is not None else None
        acct.append({"user": uid, "has_tfa": has_tfa, "tokens": len(u.get("tokens") or []),
                     "expire": u.get("expire") or 0, "comment": u.get("comment")})
    host_checks = []
    if tfa_users is not None and any(a["user"] == "root@pam" and not a["has_tfa"] for a in acct):
        host_checks.append({"level": "warn", "text": "root@pam meldet sich ohne zweiten Faktor an.",
                            "fix": "Rechenzentrum → Berechtigungen → Zwei-Faktor → Hinzufügen → TOTP für root@pam."})
    for n in node_info:
        if n.get("security_updates"):
            host_checks.append({"level": "warn", "text": f"{n['name']}: {n['security_updates']} Sicherheitsupdates offen ({', '.join(n['security_list'][:5])}).",
                                "fix": "In Proxmox: Knoten → Updates → Aktualisieren, dann „Upgrade“. Danach ggf. neu starten."})
    if not jobs:
        host_checks.append({"level": "warn", "text": "Kein automatischer Backup-Job eingerichtet.",
                            "fix": "Rechenzentrum → Backup → Hinzufügen, z. B. täglich nachts, Ziel: eigener Datenträger oder Proxmox Backup Server."})
    if not fw.get("enable"):
        host_checks.append({"level": "info", "text": "Die Proxmox-Firewall ist für das Rechenzentrum aus.",
                            "fix": "Optional. Vorher Regeln für 8006 und 22 aus dem Heimnetz anlegen, sonst sperrst du dich aus."})
    return {"version": version, "nodes": node_info, "guests": guests, "users": acct, "host_checks": host_checks,
            "backup_jobs": len(jobs), "firewall": bool(fw.get("enable")), "checked_at": now.isoformat()}


def _agent_match(db: Session, guests: list[dict]) -> None:
    names = {}
    for a in db.scalars(select(Agent).where(Agent.last_seen.is_not(None))):
        for n in (a.name, a.hostname):
            if n:
                names[n.lower().split(".")[0]] = {"id": a.id, "name": a.name,
                                                   "online": a.last_seen > datetime.utcnow() - timedelta(minutes=5)}
    for g in guests:
        g["agent"] = names.get(g["name"].lower())


# ---------- Hintergrund ----------

def run(db: Session) -> None:
    """Alle 30 Minuten: Stand holen, mit dem letzten vergleichen, Auffälliges melden."""
    if not configured():
        return
    try:
        snap = collect()
    except ProxmoxError as e:
        state.put(db, "proxmox_error", {"at": datetime.utcnow().isoformat(), "error": str(e)})
        if "Zertifikat von Proxmox hat sich geändert" in str(e):
            notify.raise_alert(db, "crit", "proxmox", "Proxmox zeigt ein anderes Zertifikat", str(e),
                               dedupe_key="proxmox-fp", dedupe_hours=24)
        return
    old = state.get(db, SNAPSHOT_KEY)
    state.put(db, "proxmox_error", None, commit=False)
    if old:
        old_users = {u["user"] for u in old.get("users", [])}
        for u in snap["users"]:
            if u["user"] not in old_users:
                notify.raise_alert(db, "crit", "proxmox", f"Neues Proxmox-Konto: {u['user']}",
                                   "Ein neues Konto mit Zugang zu Proxmox wurde angelegt. Warst du das nicht, sofort löschen "
                                   "und das root-Passwort ändern.", dedupe_key=f"pve-user:{u['user']}", dedupe_hours=24 * 30, commit=False)
            elif u["tokens"] > next((o["tokens"] for o in old["users"] if o["user"] == u["user"]), 0):
                notify.raise_alert(db, "warn", "proxmox", f"Neues API-Token für {u['user']}",
                                   "Für dieses Proxmox-Konto wurde ein API-Token angelegt. Warst du das?",
                                   dedupe_key=f"pve-token:{u['user']}:{u['tokens']}", dedupe_hours=24 * 30, commit=False)
        old_guests = {g["vmid"]: g for g in old.get("guests", [])}
        for g in snap["guests"]:
            o = old_guests.get(g["vmid"])
            if o is None:
                notify.raise_alert(db, "info", "proxmox", f"Neuer {'Container' if g['type'] == 'lxc' else 'VM'}: {g['name']} ({g['vmid']})",
                                   "Tipp: Den NetworkHelper-Agenten auch dort installieren.", dedupe_key=f"pve-new:{g['vmid']}", dedupe_hours=24 * 30, commit=False)
            elif o["status"] == "running" and g["status"] != "running" and g["onboot"]:
                notify.raise_alert(db, "warn", "proxmox", f"{g['name']} ({g['vmid']}) läuft nicht mehr",
                                   "Der Gast startet beim Booten automatisch, ist aber gerade gestoppt.",
                                   dedupe_key=f"pve-stopped:{g['vmid']}", dedupe_hours=12, commit=False)
    for g in snap["guests"]:
        for chk in g["checks"]:
            if chk["level"] == "crit":
                notify.raise_alert(db, "crit", "proxmox", f"{g['name']}: {chk['text'].split(':')[0]}",
                                   f"{chk['text']}\nSo behebst du es: {chk['fix']}", dedupe_key=f"pve-chk:{g['vmid']}:{chk['text'][:40]}",
                                   dedupe_hours=24 * 7, commit=False)
    state.put(db, SNAPSHOT_KEY, snap)


def overview(db: Session) -> dict:
    snap = state.get(db, SNAPSHOT_KEY)
    err = state.get(db, "proxmox_error")
    if snap:
        _agent_match(db, snap["guests"])
    return {"configured": configured(), "pinned": bool(settings.proxmox_fingerprint), "data": snap, "error": err}

