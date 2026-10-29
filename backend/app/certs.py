"""Zertifikate im Proxy Manager: Übersicht, Erneuern per Knopf und automatisch.

Der Proxy Manager erneuert Let's-Encrypt-Zertifikate eigentlich selbst. Klappt das nicht (häufigster Grund: Port 80
ist am Router nicht freigegeben), merkt man es erst, wenn die Seite eine Warnung zeigt. NetworkHelper erneuert
deshalb rechtzeitig selbst, übersetzt die Fehlermeldung von Let's Encrypt in verständliche Worte und meldet sich.
"""
from __future__ import annotations

import logging
import re
import threading
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from . import notify, npm, state
from .config import settings

log = logging.getLogger("networkhelper.certs")

COOLDOWN = timedelta(hours=12)  # Let's Encrypt begrenzt Fehlversuche, also nicht dauernd probieren
_running: set[int] = set()
_lock = threading.Lock()

# (Muster in der Meldung von certbot, Erklärung, Lösung)
ERRORS = [
    (r"another instance of certbot is already running",
     "Im Proxy Manager läuft gerade schon eine Erneuerung.", "Ein paar Minuten warten und erneut versuchen."),
    (r"too many (certificates|failed authorizations|new orders)|rate ?limit",
     "Let's Encrypt hat zu viele Versuche für diese Domain gezählt und blockiert vorübergehend.",
     "Je nach Grenze nach einer Stunde bis zu einer Woche erneut versuchen. Bis dahin nicht weiter probieren, jeder Versuch verlängert die Sperre."),
    (r"caa record",
     "Ein CAA-Eintrag im DNS verbietet Let's Encrypt, für diese Domain Zertifikate auszustellen.",
     "Bei Porkbun den CAA-Record löschen oder einen mit „0 issue \"letsencrypt.org\"“ ergänzen."),
    (r"nxdomain|no valid ip addresses found|dns problem: (servfail|nxdomain)|could not resolve",
     "Den Namen gibt es im DNS nicht, Let's Encrypt findet deinen Server deshalb nicht.",
     "Unter DNS einen A-Record für den Namen anlegen (oder die DynDNS-Aktualisierung prüfen) und ein paar Minuten warten."),
    (r"incorrect txt record|no txt record|dns-01|credentials|unauthorized.*api|api key",
     "Die DNS-Bestätigung ist fehlgeschlagen. Das Zertifikat nutzt den DNS-Weg (für Platzhalter wie *.domain.de), und die Zugangsdaten des DNS-Anbieters im Proxy Manager stimmen nicht oder haben keine Rechte.",
     "Im Proxy Manager das Zertifikat öffnen und die API-Zugangsdaten des DNS-Anbieters prüfen (bei Porkbun: API-Zugriff für die Domain einschalten)."),
    (r"timeout during connect|connection refused|likely firewall problem|fetching http://.*timeout|connection reset",
     "Let's Encrypt erreicht deinen Server über Port 80 nicht. Für die Bestätigung ruft es http://deine-domain/.well-known/… auf.",
     "In der FRITZ!Box unter Internet → Freigaben → Portfreigaben Port 80 (HTTP) an den Proxy Manager weiterleiten. Prüfe außerdem, ob der Name auf deine aktuelle öffentliche IP zeigt (Fehlersuche unter Erreichbarkeit). Sperrst du Länder, muss der Zugriff von Let's Encrypt (USA) erlaubt bleiben."),
    (r"invalid response from|unauthorized|404|403",
     "Let's Encrypt kommt zwar an, landet aber nicht beim Proxy Manager, oder dieser liefert die Bestätigungsdatei nicht aus.",
     "Prüfe, ob Port 80 in der FRITZ!Box wirklich zum Proxy Manager zeigt (nicht zu einem anderen Gerät) und ob im Proxy Host unter „Advanced“ eine Regel /.well-known umleitet oder sperrt. Auch eine Zugriffsliste mit Passwort kann die Bestätigung blockieren."),
    (r"not ?(a )?let'?s ?encrypt|cannot renew|custom",
     "Dieses Zertifikat wurde von Hand hochgeladen und kann nicht automatisch erneuert werden.",
     "Ein neues Zertifikat besorgen und im Proxy Manager hochladen, oder auf ein Let's-Encrypt-Zertifikat umstellen."),
]


def explain(message: str) -> tuple[str, str]:
    text = (message or "").lower()
    for pattern, why, fix in ERRORS:
        if re.search(pattern, text):
            return why, fix
    first = (message or "Unbekannter Fehler").strip().splitlines()[0][:300]
    return f"Der Proxy Manager meldet: {first}", "Im Proxy Manager unter „SSL Certificates“ das Zertifikat öffnen und das Protokoll ansehen."


def _parse(value) -> datetime | None:
    if not value:
        return None
    s = str(value).replace("T", " ").replace("Z", "").split(".")[0].split("+")[0].strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None


def _key(cert_id: int) -> str:
    return f"cert_renew:{cert_id}"


def renewable(c: dict) -> bool:
    return (c.get("provider") or "letsencrypt") == "letsencrypt"


def overview(db: Session) -> dict:
    if not npm.configured():
        return {"configured": False, "items": [], "auto": settings.cert_auto_renew, "auto_days": settings.cert_auto_renew_days}
    certs = npm.certificates()
    try:
        hosts = npm.raw_proxy_hosts()
    except npm.NpmError:
        hosts = []
    now = datetime.utcnow()
    items = []
    for c in certs:
        exp = _parse(c["expires_on"])
        last = state.get(db, _key(c["id"]))
        used = sorted({d for h in hosts if h["certificate_id"] == c["id"] for d in h["domains"]})
        items.append({**c, "expires_on": exp.isoformat() if exp else None,
                      "days_left": (exp - now).days if exp else None, "renewable": renewable(c),
                      "used_by": used, "last": last, "running": c["id"] in _running})
    items.sort(key=lambda i: (i["days_left"] is None, i["days_left"] if i["days_left"] is not None else 0))
    return {"configured": True, "items": items, "auto": settings.cert_auto_renew, "auto_days": settings.cert_auto_renew_days}


def renew(db: Session, cert_id: int, name: str = "", auto: bool = False) -> dict:
    """Erneuert ein Zertifikat und merkt sich das Ergebnis. Gibt {ok, error?, why?, fix?} zurück."""
    with _lock:
        if cert_id in _running:
            return {"ok": False, "why": "Läuft bereits.", "fix": None, "running": True}
        _running.add(cert_id)
    try:
        try:
            res = npm.renew_certificate(cert_id)
            exp = _parse((res or {}).get("expires_on"))
            out = {"ok": True, "at": datetime.utcnow().isoformat(), "auto": auto,
                   "expires_on": exp.isoformat() if exp else None}
            notify.raise_alert(db, "info", "cert", f"Zertifikat erneuert: {name or cert_id}",
                               (f"Neu gültig bis {exp:%d.%m.%Y}." if exp else "Erfolgreich erneuert.")
                               + (" Automatisch durch NetworkHelper." if auto else ""),
                               dedupe_key=f"cert-renewed:{cert_id}:{datetime.utcnow():%Y%m%d}", dedupe_hours=24, commit=False)
        except npm.NpmError as e:
            why, fix = explain(str(e))
            out = {"ok": False, "at": datetime.utcnow().isoformat(), "auto": auto, "error": str(e)[:1000], "why": why, "fix": fix}
            notify.raise_alert(db, "crit" if auto else "warn", "cert", f"Zertifikat ließ sich nicht erneuern: {name or cert_id}",
                               f"{why}\nSo behebst du es: {fix}", dedupe_key=f"cert-renew-fail:{cert_id}", dedupe_hours=12, commit=False)
        state.put(db, _key(cert_id), out)
        return out
    finally:
        with _lock:
            _running.discard(cert_id)


def renew_in_background(cert_id: int, name: str) -> bool:
    if cert_id in _running:
        return False
    from .database import SessionLocal

    def work():
        with SessionLocal() as db:
            renew(db, cert_id, name)
    threading.Thread(target=work, daemon=True, name=f"cert-{cert_id}").start()
    return True


def run(db: Session) -> None:
    """Täglich: Let's-Encrypt-Zertifikate, die bald ablaufen, selbst erneuern."""
    if not (settings.cert_auto_renew and npm.configured()):
        return
    now = datetime.utcnow()
    for c in npm.certificates():
        exp = _parse(c["expires_on"])
        if not exp or not renewable(c) or (exp - now).days >= settings.cert_auto_renew_days:
            continue
        last = state.get(db, _key(c["id"])) or {}
        at = _parse(last.get("at"))
        if at and now - at < COOLDOWN:
            continue
        log.info("Erneuere Zertifikat %s (läuft am %s ab)", c["name"], exp)
        renew(db, c["id"], c["name"], auto=True)
