"""AdGuard Home: Status, blockierte Anfragen, Warnungen bei Schadseiten und lokale DNS-Umschreibungen.

AdGuard Home ist der DNS-Server im Heimnetz. Er filtert Werbung und gefährliche Seiten für alle Geräte. NetworkHelper
liest über die API (Basic Auth) Status, Statistik und Abfrageprotokoll, schlägt DNS-Umschreibungen vor (eigene
Domains im Heimnetz direkt zum Proxy Manager, ohne Umweg über den Router) und meldet, wenn Geräte Schadseiten
aufrufen wollten oder AdGuard ausfällt.
"""
from __future__ import annotations

import ipaddress
import socket
from datetime import datetime, timedelta
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from . import notify, npm, state
from .config import settings
from .netutil import classify


class AdGuardError(RuntimeError):
    pass


def configured() -> bool:
    return bool(settings.adguard_url)


def _req(method: str, path: str, json: dict | None = None, params: dict | None = None, timeout: float = 10):
    if not configured():
        raise AdGuardError("AdGuard Home ist nicht eingerichtet (Administration → DNS).")
    auth = (settings.adguard_user, settings.adguard_password) if settings.adguard_user else None
    try:
        r = httpx.request(method, settings.adguard_url.rstrip("/") + "/control" + path, json=json, params=params,
                          auth=auth, timeout=timeout, verify=False)
    except httpx.HTTPError as e:
        raise AdGuardError(f"AdGuard Home nicht erreichbar ({e.__class__.__name__}). Stimmt die Adresse mit Port (meist 80 oder 3000)?")
    if r.status_code in (401, 403):
        raise AdGuardError("Anmeldung an AdGuard Home fehlgeschlagen: Benutzername oder Passwort stimmen nicht.")
    if r.status_code == 404:
        raise AdGuardError("Unter dieser Adresse antwortet kein AdGuard Home (oder eine sehr alte Version).")
    if r.status_code >= 400:
        raise AdGuardError(f"AdGuard Home meldet Fehler {r.status_code}: {r.text.strip()[:200]}")
    if not r.content:
        return None
    try:
        return r.json()
    except ValueError:
        return r.text


# ---------- Lesen ----------

def status() -> dict:
    s = _req("GET", "/status") or {}
    return {"version": s.get("version"), "running": bool(s.get("running", True)),
            "protection": bool(s.get("protection_enabled")), "protection_disabled_until": s.get("protection_disabled_until"),
            "protection_disabled_ms": s.get("protection_disabled_duration") or 0,
            "dns_addresses": s.get("dns_addresses") or [], "dns_port": s.get("dns_port")}


def _top(items, n=8) -> list[dict]:
    out = []
    for entry in items or []:
        if isinstance(entry, dict):
            for k, v in entry.items():
                out.append({"name": k, "count": int(v or 0)})
    return out[:n]


def stats() -> dict:
    s = _req("GET", "/stats") or {}
    total = int(s.get("num_dns_queries") or 0)
    blocked = int(s.get("num_blocked_filtering") or 0)
    malware = int(s.get("num_replaced_safebrowsing") or 0)
    adult = int(s.get("num_replaced_parental") or 0)
    return {"queries": total, "blocked": blocked, "malware": malware, "parental": adult,
            "blocked_pct": round(100 * (blocked + malware + adult) / total, 1) if total else 0,
            "avg_ms": round(float(s.get("avg_processing_time") or 0) * 1000, 1),
            "top_blocked": _top(s.get("top_blocked_domains")), "top_clients": _top(s.get("top_clients")),
            "top_queried": _top(s.get("top_queried_domains")), "hours": len(s.get("dns_queries") or []) or 24}


REASONS = {
    "FilteredBlackList": "Filterliste", "FilteredSafeBrowsing": "Schadseite/Phishing", "FilteredParental": "Jugendschutz",
    "FilteredSafeSearch": "SafeSearch", "FilteredBlockedService": "Gesperrter Dienst", "FilteredInvalid": "Ungültig",
}


def _entry(e: dict) -> dict:
    q = e.get("question") or {}
    rules = e.get("rules") or ([{"text": e["rule"]}] if e.get("rule") else [])
    info = e.get("client_info") or {}
    return {"time": e.get("time"), "domain": (q.get("name") or q.get("host") or "").rstrip("."), "type": q.get("type"),
            "client": e.get("client"), "client_name": info.get("name") or None,
            "reason": e.get("reason"), "reason_label": REASONS.get(e.get("reason"), e.get("reason")),
            "rule": (rules[0].get("text") if rules else None)}


def blocked(limit: int = 50, status_filter: str = "blocked") -> list[dict]:
    data = _req("GET", "/querylog", params={"limit": limit, "response_status": status_filter}) or {}
    return [_entry(e) for e in (data.get("data") or [])]


def check_host(name: str) -> dict:
    """Würde AdGuard den Namen sperren oder umschreiben?"""
    r = _req("GET", "/filtering/check_host", params={"name": name}) or {}
    reason = r.get("reason") or ""
    rules = r.get("rules") or []
    answer = None
    if reason == "Rewrite" or reason == "RewriteEtcHosts" or reason == "RewriteRule":
        ips = r.get("ip_addrs") or []
        answer = (ips[0] if ips else None) or r.get("cname")
    return {"blocked": reason.startswith("Filtered") and reason != "FilteredSafeSearch", "reason": reason,
            "reason_label": REASONS.get(reason, reason), "rule": (rules[0].get("text") if rules else r.get("rule")) or None,
            "rewrite": answer}


def update_info() -> dict | None:
    try:
        v = _req("POST", "/version.json", json={"recheck_now": False}, timeout=15) or {}
    except AdGuardError:
        return None
    if not isinstance(v, dict) or v.get("disabled"):
        return None
    return {"new_version": v.get("new_version"), "url": v.get("announcement_url")} if v.get("new_version") else None


def rewrites() -> list[dict]:
    return [{"domain": r.get("domain"), "answer": r.get("answer")} for r in (_req("GET", "/rewrite/list") or [])]


# ---------- Ändern ----------

def set_protection(enabled: bool, minutes: int = 0) -> None:
    body = {"enabled": enabled}
    if not enabled and minutes:
        body["duration"] = int(minutes) * 60_000
    _req("POST", "/protection", json=body)


def add_rewrite(domain: str, answer: str) -> None:
    _req("POST", "/rewrite/add", json={"domain": domain, "answer": answer})


def delete_rewrite(domain: str, answer: str) -> None:
    _req("POST", "/rewrite/delete", json={"domain": domain, "answer": answer})


def allow_domain(domain: str) -> str:
    """Gibt einen Namen frei: eigene Regel @@||domain^ (wirkt vor allen Filterlisten)."""
    rule = f"@@||{domain}^$important"
    st = _req("GET", "/filtering/status") or {}
    rules = list(st.get("user_rules") or [])
    if rule not in rules:
        rules.append(rule)
        _req("POST", "/filtering/set_rules", json={"rules": rules})
    return rule


# ---------- Vorschläge ----------

def npm_lan_ip() -> str | None:
    """Die Heimnetz-Adresse des Proxy Managers, abgeleitet aus seiner Verwaltungsadresse."""
    host = urlparse(settings.npm_url or "").hostname
    if not host:
        return None
    try:
        ip = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            return None
    return ip if classify(ip) == "private" else None


def _covered(name: str, existing: list[dict]) -> dict | None:
    for r in existing:
        d = (r["domain"] or "").lower()
        if d == name or (d.startswith("*.") and name.endswith(d[1:])):
            return r
    return None


def suggestions(existing: list[dict]) -> dict:
    """Eigene Domains, die im Heimnetz direkt zum Proxy Manager zeigen sollten."""
    ip = npm_lan_ip()
    if not ip or not npm.configured():
        return {"ip": ip, "items": [], "wrong": []}
    try:
        names = sorted({d for h in npm.raw_proxy_hosts() if h["enabled"] for d in h["domains"] if not d.startswith("*.")})
    except npm.NpmError:
        return {"ip": ip, "items": [], "wrong": []}
    items, wrong = [], []
    for n in names:
        r = _covered(n, existing)
        if r is None:
            items.append(n)
        elif r["answer"] != ip and r["answer"] not in names:
            wrong.append({"domain": n, "rule": r["domain"], "answer": r["answer"]})
    bases: dict[str, int] = {}
    for n in items:
        base = ".".join(n.split(".")[-2:])
        bases[base] = bases.get(base, 0) + 1
    wildcards = [f"*.{b}" for b, c in bases.items() if c >= 2]
    return {"ip": ip, "items": items, "wildcards": wildcards, "wrong": wrong}


# ---------- Hintergrund ----------

def overview(db: Session) -> dict:
    out = {"configured": configured(), "url": settings.adguard_url}
    if not configured():
        return out
    try:
        out["status"] = status()
        out["stats"] = stats()
        out["blocked"] = blocked(40)
        out["malware"] = blocked(20, "blocked_safebrowsing")
        rw = rewrites()
        out["rewrites"] = rw
        out["suggest"] = suggestions(rw)
        out["update"] = update_info()
    except AdGuardError as e:
        out["error"] = str(e)
    out["last_ok"] = state.get(db, "adguard_last_ok")
    return out


def run(db: Session) -> None:
    """Alle 10 Minuten: läuft AdGuard, ist der Schutz an, wollte ein Gerät eine Schadseite aufrufen?"""
    if not configured():
        return
    now = datetime.utcnow()
    try:
        st = status()
    except AdGuardError as e:
        last = state.get(db, "adguard_last_ok")
        down_since = state.get(db, "adguard_down_since") or now.isoformat()
        state.put(db, "adguard_down_since", down_since)
        if datetime.fromisoformat(down_since) <= now - timedelta(minutes=9):
            notify.raise_alert(db, "crit", "adguard", "AdGuard Home antwortet nicht",
                               f"{e}\nSolange AdGuard nicht läuft, können Geräte im Heimnetz, die ihn als DNS-Server nutzen, "
                               "keine Seiten mehr aufrufen. Prüfe den Container bzw. die VM von AdGuard Home."
                               + (f"\nZuletzt erreichbar: {last[:16].replace('T', ' ')} UTC" if last else ""),
                               dedupe_key=f"adguard-down:{down_since[:13]}", dedupe_hours=24)
        return
    state.put(db, "adguard_last_ok", now.isoformat(), commit=False)
    if state.get(db, "adguard_down_since"):
        state.put(db, "adguard_down_since", None, commit=False)
    if not st["protection"] and not st["protection_disabled_ms"]:
        notify.raise_alert(db, "warn", "adguard", "AdGuard-Schutz ist ausgeschaltet",
                           "Der Filter ist dauerhaft pausiert, Werbung und Schadseiten werden nicht mehr gesperrt. "
                           "Unter DNS → AdGuard Home wieder einschalten.", dedupe_key="adguard-off", dedupe_hours=24, commit=False)
    seen = state.get(db, "adguard_malware_seen") or ""
    newest = seen
    hits: dict[str, list[str]] = {}
    try:
        for e in blocked(100, "blocked_safebrowsing"):
            t = e["time"] or ""
            if t <= seen:
                continue
            newest = max(newest, t)
            who = e["client_name"] or e["client"] or "?"
            hits.setdefault(who, [])
            if e["domain"] not in hits[who]:
                hits[who].append(e["domain"])
    except AdGuardError:
        pass
    if seen:  # beim ersten Lauf nur merken, keine alten Treffer melden
        for who, domains in hits.items():
            notify.raise_alert(db, "warn", "adguard", f"Gerät „{who}“ wollte eine gefährliche Seite aufrufen",
                               "AdGuard hat gesperrt: " + ", ".join(domains[:8]) + ".\nEinmal ist oft ein Klick auf einen Link in einer "
                               "Spam-Mail. Kommt es öfter vor, kann auf dem Gerät Schadsoftware laufen: Virenscan, Browser-Erweiterungen prüfen.",
                               dedupe_key=f"adguard-malware:{who}:{now:%Y%m%d}", dedupe_hours=24, commit=False)
    state.put(db, "adguard_malware_seen", newest or "0000")
