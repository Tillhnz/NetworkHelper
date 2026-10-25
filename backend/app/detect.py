"""Auffällige Zugriffe erkennen und auf Wunsch sperren.

Regeln (je öffentliche IP, Fenster 10 Minuten):
- scanner:     Anfragen an typische Angriffsziele (/.env, /wp-login.php, /phpmyadmin …)
- badagent:    bekannte Angriffswerkzeuge im User-Agent (sqlmap, nikto, zgrab …)
- bruteforce:  mindestens 20 Antworten 401/403 (Anmeldeversuche)
- notfound:    mindestens 60 Antworten 404 (Verzeichnis-Scan)
- flood:       mindestens 1200 Anfragen (ungewöhnlich hohe Last)
Ein Vorfall fasst alle Treffer einer IP und Regel innerhalb von 24 Stunden zusammen.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from . import notify, state
from .accesslog import block_cache
from .config import settings
from .models import AccessEvent, BlockEntry, Incident
from .netutil import ip_in, is_public, normalize_cidr

WINDOW = timedelta(minutes=10)
MERGE = timedelta(hours=24)
RANK = {"info": 0, "warn": 1, "crit": 2}

SCANNER_RE = re.compile(
    r"(?i)(^/\.env|/\.git/|/\.aws/|/\.ssh/|/\.htpasswd|/\.DS_Store|wp-login\.php|/wp-admin|/wp-content/plugins|xmlrpc\.php|"
    r"phpmyadmin|/pma/|/myadmin|/cgi-bin/|/boaform|/HNAP1|/actuator|/vendor/phpunit|eval-stdin\.php|/server-status|"
    r"/owa/auth|/ecp/|/autodiscover|/remote/login|/global-protect|/\+CSCOE\+|/solr/|/console/login|/manager/html|"
    r"/shell\b|/setup\.cgi|/goform/|/cdn-cgi/trace\.php|\.\./\.\./|/etc/passwd|/config\.json$|/sftp-config\.json|"
    r"/\.vscode/|/backup\.(zip|sql|tar)|/db\.sql|/dump\.sql|/admin\.php|/xampp|/druid/|/telescope/requests|/_ignition)"
)
# Eindeutige Angriffswerkzeuge: schon ein Treffer ist eine Warnung wert
BAD_UA_RE = re.compile(
    r"(?i)(sqlmap|nikto|nmap scripting|masscan|nuclei|gobuster|dirbuster|dirb/|wpscan|ffuf|feroxbuster|"
    r"hello, world|zmeu|morfeus|jorgee|fuzz faster|acunetix|netsparker|openvas|whatweb|xray)"
)
# Allerweltsprogramme, die Bots gern benutzen; erst bei vielen Anfragen auffällig.
# Forschungs-Scanner (Censys, Palo Alto Expanse, internet-measurement …) zählen nicht: sie ordnet „Wer & warum“ ein.
WEAK_UA_RE = re.compile(r"(?i)(zgrab|python-requests/2\.2[0-5]|go-http-client/1\.1$|libwww-perl|curl/7\.(2|3)\d\.|httpx - open-source)")
WEAK_UA_MIN = 20

KIND_TEXT = {
    "scanner": "Suche nach Schwachstellen",
    "badagent": "Angriffswerkzeug erkannt",
    "bruteforce": "Viele fehlgeschlagene Anmeldungen",
    "notfound": "Verzeichnis-Scan (viele 404)",
    "flood": "Sehr viele Anfragen",
}


def block_lookup(db: Session):
    """Liefert eine Funktion ip -> BlockEntry|None über die aktiven Sperren (einmal gelesen)."""
    entries = active_blocks(db)

    def find(ip: str) -> BlockEntry | None:
        return next((b for b in entries if ip_in(ip, b.cidr)), None)
    return find


def is_blocked(db: Session, ip: str) -> BlockEntry | None:
    return block_lookup(db)(ip)


def add_block(db: Session, cidr: str, reason: str = "", hours: float | None = None, by: str | None = None, auto: bool = False) -> BlockEntry:
    cidr = normalize_cidr(cidr)
    expires = datetime.utcnow() + timedelta(hours=hours) if hours else None
    row = db.scalar(select(BlockEntry).where(BlockEntry.cidr == cidr))
    if row is None:
        row = BlockEntry(cidr=cidr, reason=(reason or None) and reason[:200], expires_at=expires, created_by=by, auto=auto)
        db.add(row)
    else:  # Verlängern statt doppelt anlegen; eine dauerhafte Sperre bleibt dauerhaft
        if expires is None:
            row.expires_at = None
        elif row.expires_at is not None:
            row.expires_at = max(expires, row.expires_at)
        if reason:
            row.reason = reason[:200]
    db.commit()
    block_cache.invalidate()
    return row


def active_blocks(db: Session) -> list[BlockEntry]:
    now = datetime.utcnow()
    return db.scalars(select(BlockEntry).where((BlockEntry.expires_at.is_(None)) | (BlockEntry.expires_at > now)).order_by(BlockEntry.id)).all()


def prune_blocks(db: Session) -> int:
    rows = db.scalars(select(BlockEntry).where(BlockEntry.expires_at.is_not(None), BlockEntry.expires_at <= datetime.utcnow())).all()
    for r in rows:
        db.delete(r)
    if rows:
        db.commit()
        block_cache.invalidate()
    return len(rows)


def _upsert(db: Session, ip: str, kind: str, severity: str, hits: int, hosts: set[str], samples: list[dict], ev: AccessEvent, now: datetime) -> tuple[Incident, bool]:
    inc = db.scalar(select(Incident).where(Incident.ip == ip, Incident.kind == kind, Incident.last_seen >= now - MERGE).order_by(Incident.id.desc()).limit(1))
    created = inc is None
    if created:
        inc = Incident(ip=ip, kind=kind, severity=severity, first_seen=now, last_seen=now, count=0, country=ev.country, as_org=ev.as_org)
        db.add(inc)
    escalated = not created and RANK[severity] > RANK.get(inc.severity, 0)
    inc.count = (inc.count or 0) + hits
    inc.last_seen = now
    if RANK[severity] > RANK.get(inc.severity, 0):
        inc.severity = severity
    known = set(filter(None, (inc.hosts or "").split(",")))
    inc.hosts = ",".join(sorted(known | hosts))[:400]
    old = json.loads(inc.sample) if inc.sample else []
    inc.sample = json.dumps((old + samples)[-8:])
    if escalated:
        inc.acknowledged = False
    return inc, created or escalated


def run(db: Session, now: datetime | None = None, limit: int = 50000) -> list[Incident]:
    """Prüft neue Zugriffe seit dem letzten Lauf. Gibt neue oder verschärfte Vorfälle zurück."""
    now = now or datetime.utcnow()
    last_id = state.get(db, "detect_last_id", 0) or 0
    events = db.scalars(select(AccessEvent).where(AccessEvent.id > last_id).order_by(AccessEvent.id).limit(limit)).all()
    if not events:
        return []
    state.put(db, "detect_last_id", events[-1].id, commit=False)
    if not settings.detect_enabled:
        db.commit()
        return []

    from . import exposure, publicip
    own_ip = publicip.info(db).get("ip")
    periods = publicip.own_periods(db)
    by_ip: dict[str, list[AccessEvent]] = defaultdict(list)
    for e in events:
        if publicip.is_own(periods, e.ip, e.ts):
            continue  # du selbst von zu Hause über deine Domain (öffentliche IP), nie ein Angriff
        if is_public(e.ip) and not e.blocked and not exposure.is_own_check(e.ip, e.user_agent, own_ip):
            by_ip[e.ip].append(e)
    if not by_ip:
        db.commit()
        return []

    # Zählungen im Fenster aus der Datenbank (enthält auch Zugriffe aus früheren Läufen)
    since = now - WINDOW
    agg = {}
    ips = list(by_ip)
    for i in range(0, len(ips), 500):
        chunk = ips[i:i + 500]
        q = (select(AccessEvent.ip, func.count(),
                    func.sum(case((AccessEvent.status.in_([401, 403]), 1), else_=0)),
                    func.sum(case((AccessEvent.status == 404, 1), else_=0)))
             .where(AccessEvent.ts >= since, AccessEvent.ip.in_(chunk), AccessEvent.blocked.is_not(True))
             .group_by(AccessEvent.ip))
        for ip, total, auth, nf in db.execute(q):
            agg[ip] = (total or 0, auth or 0, nf or 0)

    changed: list[Incident] = []  # neu oder verschärft: Meldung
    touched: dict[int, Incident] = {}  # alle bearbeiteten: Prüfung auf automatische Sperre
    for ip, evs in by_ip.items():
        total, auth, nf = agg.get(ip, (len(evs), 0, 0))
        hosts = {e.host for e in evs}
        sample = lambda subset: [{"ts": e.ts.isoformat(), "host": e.host, "path": e.path[:200], "status": e.status, "ua": (e.user_agent or "")[:120]} for e in subset[-3:]]
        hits = [e for e in evs if SCANNER_RE.search(e.path)]
        if hits:
            sev = "warn" if len(hits) >= 10 else "info"
            inc, new = _upsert(db, ip, "scanner", sev, len(hits), {e.host for e in hits}, sample(hits), evs[-1], now)
            touched[id(inc)] = inc
            if new:
                changed.append(inc)
        bad = [e for e in evs if e.user_agent and BAD_UA_RE.search(e.user_agent)]
        weak = [e for e in evs if e.user_agent and not BAD_UA_RE.search(e.user_agent) and WEAK_UA_RE.search(e.user_agent)]
        if bad or len(weak) >= WEAK_UA_MIN:
            sev = "warn" if bad else "info"
            hits_ = bad or weak
            inc, new = _upsert(db, ip, "badagent", sev, len(hits_), {e.host for e in hits_}, sample(hits_), evs[-1], now)
            touched[id(inc)] = inc
            if new:
                changed.append(inc)
        auth_new = [e for e in evs if e.status in (401, 403)]
        if auth >= 20 and auth_new:
            inc, new = _upsert(db, ip, "bruteforce", "crit", len(auth_new), {e.host for e in auth_new}, sample(auth_new), evs[-1], now)
            touched[id(inc)] = inc
            if new:
                changed.append(inc)
        nf_new = [e for e in evs if e.status == 404]
        if nf >= 60 and nf_new:
            inc, new = _upsert(db, ip, "notfound", "warn", len(nf_new), {e.host for e in nf_new}, sample(nf_new), evs[-1], now)
            touched[id(inc)] = inc
            if new:
                changed.append(inc)
        if total >= 1200:
            inc, new = _upsert(db, ip, "flood", "warn", len(evs), hosts, sample(evs), evs[-1], now)
            touched[id(inc)] = inc
            if new:
                changed.append(inc)
    db.commit()

    blocked_now: dict[str, BlockEntry] = {}
    if settings.auto_block:
        for inc in touched.values():
            serious = inc.severity == "crit" or (inc.kind in ("scanner", "badagent") and inc.severity == "warn")
            if serious and inc.ip not in blocked_now and not is_blocked(db, inc.ip) and not publicip.is_own(periods, inc.ip, now):
                blocked_now[inc.ip] = add_block(db, inc.ip, f"Automatisch: {KIND_TEXT[inc.kind]}", hours=settings.auto_block_hours,
                                                by="automatisch", auto=True)
    for inc in changed:
        if RANK[inc.severity] >= 1:
            where = f" ({inc.country})" if inc.country else ""
            body = f"IP: {inc.ip}{where}{', ' + inc.as_org if inc.as_org else ''}\nZiele: {inc.hosts or '-'}\nTreffer bisher: {inc.count}"
            if inc.ip in blocked_now:
                body += f"\nDie Adresse ist für {settings.auto_block_hours} Stunden gesperrt."
            notify.raise_alert(db, inc.severity, "incident", f"{KIND_TEXT[inc.kind]} von {inc.ip}", body,
                               dedupe_key=f"incident:{inc.ip}:{inc.kind}:{inc.severity}", dedupe_hours=24)
    for ip in blocked_now:
        if not any(i.ip == ip for i in changed):
            notify.raise_alert(db, "warn", "block", f"{ip} automatisch gesperrt", f"Für {settings.auto_block_hours} Stunden wegen anhaltender Angriffe.",
                               dedupe_key=f"autoblock:{ip}", dedupe_hours=24)
    return changed


def forget_own(db: Session) -> dict:
    """Räumt Vorfälle und automatische Sperren auf, die deine eigene öffentliche IP (auch frühere) betreffen."""
    from . import publicip
    periods = publicip.own_periods(db)
    own = {p[0] for p in periods}
    if not own:
        return {"incidents": 0, "blocks": 0}
    incs = db.scalars(select(Incident).where(Incident.ip.in_(own))).all()
    n_inc = 0
    for inc in incs:
        if publicip.is_own(periods, inc.ip, inc.last_seen):
            db.delete(inc)
            n_inc += 1
    n_blk = 0
    for b in db.scalars(select(BlockEntry).where(BlockEntry.auto.is_(True), BlockEntry.cidr.in_(list(own)))):
        db.delete(b)
        n_blk += 1
    if n_inc or n_blk:
        db.commit()
        block_cache.invalidate()
    return {"incidents": n_inc, "blocks": n_blk}
