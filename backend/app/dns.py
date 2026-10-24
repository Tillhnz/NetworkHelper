"""DNS-Automatik: DynDNS über Porkbun und Abgleich mit den Proxy Hosts des Nginx Proxy Managers."""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import notify, npm, porkbun, publicip, state
from .config import settings
from .models import DynRecord, Monitor, SiteCheck

log = logging.getLogger("networkhelper.dns")
ADDRESS_TYPES = ("A", "AAAA", "CNAME", "ALIAS")


def split_fqdn(fqdn: str, domains: list[str]) -> tuple[str, str] | None:
    """'cloud.home.example.de' + ['example.de'] -> ('example.de', 'cloud.home'). Längste passende Domain gewinnt."""
    fqdn = fqdn.lower().rstrip(".")
    best = None
    for d in domains:
        if fqdn == d or fqdn.endswith("." + d):
            if best is None or len(d) > len(best):
                best = d
    if best is None:
        return None
    return best, fqdn[: -len(best)].rstrip(".")


def covered_by(name: str, recs: list[dict]) -> dict | None:
    """Record, der diesen Namen auflöst: exakt oder per Platzhalter (*.example.de, *.home.example.de)."""
    addr = [r for r in recs if r["type"] in ADDRESS_TYPES]
    for r in addr:
        if r["name"] == name:
            return r
    parts = name.split(".") if name else []
    for i in range(len(parts)):
        wild = ".".join(["*"] + parts[i + 1:])
        for r in addr:
            if r["name"] == wild:
                return r
    return None


# ---------- DynDNS ----------

def run_dyndns(db: Session, force: bool = False) -> dict:
    """Zieht alle DynDNS-Records auf die aktuelle öffentliche IP nach."""
    result = {"ip": None, "updated": [], "errors": [], "unchanged": 0}
    rows = db.scalars(select(DynRecord).where(DynRecord.enabled.is_(True))).all()
    ip = publicip.current(db, refresh=True)
    result["ip"] = ip
    if not rows or not porkbun.configured():
        return result
    if not ip:
        result["errors"].append("Die öffentliche IP ließ sich nicht ermitteln.")
        return result
    cache: dict[str, list[dict]] = {}
    now = datetime.utcnow()
    for row in rows:
        if row.last_ip == ip and not force and not row.last_error:
            result["unchanged"] += 1
            continue
        label = f"{row.name + '.' if row.name else ''}{row.domain}"
        try:
            if row.domain not in cache:
                cache[row.domain] = porkbun.records(row.domain)
            current = next((r for r in cache[row.domain] if r["name"] == row.name and r["type"] == row.type), None)
            if current is None:
                porkbun.create(row.domain, row.name, row.type, ip, 600, notes="NetworkHelper DynDNS")
                result["updated"].append(label)
            elif current["content"] != ip:
                porkbun.edit_by_name_type(row.domain, row.type, row.name, ip, current.get("ttl") or 600)
                result["updated"].append(label)
            else:
                result["unchanged"] += 1
            row.last_ip, row.last_update, row.last_error = ip, now, None
        except porkbun.PorkbunError as e:
            row.last_error = str(e)[:300]
            result["errors"].append(f"{label}: {e}")
    db.commit()
    state.put(db, "dyndns_last", {**result, "at": now.isoformat()})
    if result["updated"]:
        notify.raise_alert(db, "info", "dns", f"DynDNS: {len(result['updated'])} Record(s) auf {ip} gesetzt", "\n".join(result["updated"]),
                           dedupe_key=f"dyndns:{ip}:{','.join(sorted(result['updated']))}", dedupe_hours=1)
    if result["errors"]:
        notify.raise_alert(db, "warn", "dns", "DynDNS-Aktualisierung fehlgeschlagen", "\n".join(result["errors"]),
                           dedupe_key="dyndns:error:" + hashlib.sha1("\n".join(result["errors"]).encode()).hexdigest()[:16], dedupe_hours=12)
    return result


def ensure_dyn(db: Session, domain: str, name: str, rtype: str = "A", enabled: bool = True) -> DynRecord:
    row = db.scalar(select(DynRecord).where(DynRecord.domain == domain, DynRecord.name == name, DynRecord.type == rtype))
    if row is None:
        row = DynRecord(domain=domain, name=name, type=rtype, enabled=enabled)
        db.add(row)
    else:
        row.enabled = enabled
    db.commit()
    return row


def create_for_host(db: Session, domain: str, name: str) -> dict:
    """Legt einen Record für einen Proxy Host an: A mit öffentlicher IP (DynDNS) oder CNAME auf die Hauptdomain."""
    if settings.dns_new_record_type == "CNAME" and name:
        rid = porkbun.create(domain, name, "CNAME", domain, 600, notes="NetworkHelper")
        return {"id": rid, "type": "CNAME", "content": domain}
    ip = publicip.current(db)
    if not ip:
        raise porkbun.PorkbunError("Die öffentliche IP ist unbekannt. Prüfe die Internetverbindung des Servers.")
    rid = porkbun.create(domain, name, "A", ip, 600, notes="NetworkHelper DynDNS")
    row = ensure_dyn(db, domain, name, "A")
    row.last_ip, row.last_update = ip, datetime.utcnow()
    db.commit()
    return {"id": rid, "type": "A", "content": ip}


# ---------- Abgleich mit dem Proxy Manager ----------

def npm_overview(db: Session) -> dict:
    """Welche Proxy Hosts einen DNS-Record bei Porkbun haben und welche nicht."""
    hosts = npm.proxy_hosts()
    domains = porkbun.managed_domains() if porkbun.configured() else []
    cache: dict[str, list[dict]] = {}
    items = []
    for h in hosts:
        for fqdn in h["domains"]:
            item = {"fqdn": fqdn, "host_id": h["id"], "enabled": h["enabled"], "forward": h["forward"], "ssl": h["ssl"],
                    "domain": None, "name": None, "status": "foreign", "record": None}
            split = split_fqdn(fqdn, domains)
            if split:
                domain, name = split
                item.update(domain=domain, name=name)
                if domain not in cache:
                    try:
                        cache[domain] = porkbun.records(domain)
                    except porkbun.PorkbunError as e:
                        cache[domain] = []
                        item["error"] = str(e)
                rec = covered_by(name, cache[domain])
                item["record"] = rec
                item["status"] = "ok" if rec else "missing"
            items.append(item)
    items.sort(key=lambda i: ({"missing": 0, "ok": 1, "foreign": 2}[i["status"]], i["fqdn"]))
    return {"items": items, "domains": domains}


def sync_from_npm(db: Session) -> dict:
    """Regelmäßiger Abgleich: Monitore und Zertifikatsprüfungen für Proxy Hosts, auf Wunsch fehlende DNS-Records."""
    out = {"monitors": 0, "sites": 0, "dns": [], "error": None}
    try:
        hosts = npm.proxy_hosts()
    except npm.NpmError as e:
        out["error"] = str(e)
        state.put(db, "npm_sync", {**out, "at": datetime.utcnow().isoformat()})
        return out
    fqdns = sorted({d for h in hosts if h["enabled"] for d in h["domains"] if "*" not in d})
    # Zertifikats- und Header-Prüfung für jeden Hostnamen
    known = {s.host: s for s in db.scalars(select(SiteCheck))}
    for f in fqdns:
        if f not in known:
            db.add(SiteCheck(host=f, source="npm", enabled=True))
            out["sites"] += 1
    for host, s in known.items():
        if s.source == "npm" and host not in fqdns:
            db.delete(s)
    # Erreichbarkeit: ein Monitor je Proxy Host (erste Domain)
    if settings.npm_auto_monitors:
        existing = {m.url: m for m in db.scalars(select(Monitor))}
        wanted = set()
        for h in hosts:
            if not h["enabled"] or not h["domains"] or "*" in h["domains"][0]:
                continue
            url = f"{'https' if h['ssl'] else 'http'}://{h['domains'][0]}/"
            wanted.add(url)
            if url not in existing:
                db.add(Monitor(name=h["domains"][0], url=url, source="npm", expect="200-499"))
                out["monitors"] += 1
        for url, m in existing.items():
            if m.source == "npm" and url not in wanted:
                db.delete(m)
    db.commit()
    # Fehlende DNS-Records anlegen
    if settings.npm_auto_dns and porkbun.configured():
        try:
            ov = npm_overview(db)
            for item in ov["items"]:
                if item["status"] == "missing" and item["enabled"]:
                    try:
                        create_for_host(db, item["domain"], item["name"])
                        out["dns"].append(item["fqdn"])
                    except porkbun.PorkbunError as e:
                        out["error"] = str(e)
        except (npm.NpmError, porkbun.PorkbunError) as e:
            out["error"] = str(e)
        if out["dns"]:
            notify.raise_alert(db, "info", "dns", f"{len(out['dns'])} DNS-Record(s) für neue Proxy Hosts angelegt", "\n".join(out["dns"]))
    state.put(db, "npm_sync", {**out, "at": datetime.utcnow().isoformat(), "hosts": len(hosts)})
    return out
