"""Waren Angriffe erfolgreich? Prüft die eigenen Hosts auf offen lesbare Geheimnisse und Admin-Oberflächen.

Zwei Blickwinkel:
1. Aus den Protokollen: Welche typischen Angriffs-Anfragen (/.env, /.git/config, /wp-login.php …) hat ein Dienst
   mit „200 OK“ beantwortet? Das allein heißt noch nichts: Viele Web-Apps liefern für jede unbekannte Adresse ihre
   Startseite aus.
2. Selbsttest: NetworkHelper ruft dieselben Adressen bei deinen eigenen Hosts auf und schaut in den Inhalt. Nur wenn
   dort wirklich eine .env-Datei, ein Git-Repository, ein privater Schlüssel usw. steht, gilt die Lücke als bestätigt.
   Zum Vergleich wird vorher eine sicher nicht vorhandene Adresse abgerufen, um „liefert immer die Startseite“ zu erkennen.

Es werden nur GET-Anfragen an Hosts gestellt, die in NetworkHelper als eigene Seiten eingetragen sind. Gefundene
Inhalte werden nie gespeichert: Als Beleg dient nur, welche Schlüssel betroffen sind (Werte werden geschwärzt).
"""
from __future__ import annotations

import hashlib
import logging
import re
import secrets
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

import httpx
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from . import notify, publicip, state
from .detect import SCANNER_RE
from .models import AccessEvent, Exposure, SiteCheck
from .netutil import classify

log = logging.getLogger("networkhelper.exposure")

USER_AGENT = "NetworkHelper-Exposure-Check/1.0 (Selbsttest der eigenen Seiten)"
MAX_BYTES = 64 * 1024
LOG_DAYS = 30


def _mask_env(text: str) -> str | None:
    keys = re.findall(r"(?m)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]{1,60})\s*=\s*\S", text)
    if len(keys) < 2 or "<html" in text[:500].lower():
        return None
    secret_like = [k for k in keys if re.search(r"(?i)pass|secret|key|token|pwd|auth|private|dsn|database_url|credential", k)]
    show = (secret_like or keys)[:6]
    more = len(keys) - len(show)
    return ", ".join(f"{k}=•••" for k in show) + (f" und {more} weitere" if more > 0 else "")


def _rx(pattern: str, evidence: str, flags=re.I | re.M) -> Callable[[str, bytes], str | None]:
    rx = re.compile(pattern, flags)
    return lambda text, raw: evidence if rx.search(text) else None


@dataclass(frozen=True)
class Probe:
    key: str
    paths: tuple[str, ...]
    label: str
    severity: str  # crit | warn
    check: Callable[[str, bytes], str | None]
    fix: str


PROBES = [
    Probe("env", ("/.env", "/.env.local", "/.env.production", "/.env.backup", "/api/.env"), ".env-Datei mit Zugangsdaten", "crit",
          lambda text, raw: _mask_env(text),
          "Die Datei gehört nicht in den Web-Ordner. Verschiebe sie eine Ebene höher oder sperre Pfade mit Punkt am Anfang im Proxy Manager "
          "(Custom Location oder Advanced: location ~ /\\. { deny all; }). Danach unbedingt alle Passwörter und Schlüssel aus der Datei ändern."),
    Probe("git", ("/.git/config", "/.git/HEAD"), "Git-Repository (Quellcode mit Verlauf)", "crit",
          lambda text, raw: "Git-Konfiguration ([core]) lesbar" if re.search(r"^\[core\]", text, re.M) else
          ("Git-HEAD lesbar (ref: refs/…)" if re.match(r"ref: refs/", text) else None),
          "Lösche den Ordner .git auf dem Server oder sperre ihn (location ~ /\\.git { deny all; }). Wer ihn lesen konnte, hat den ganzen Quellcode "
          "samt früher eingecheckter Passwörter: Zugangsdaten aus dem Verlauf ändern."),
    Probe("ssh", ("/.ssh/id_rsa", "/.ssh/id_ed25519", "/id_rsa"), "Privater SSH-Schlüssel", "crit",
          _rx(r"-----BEGIN (OPENSSH|RSA|EC|DSA)? ?PRIVATE KEY-----", "Privater Schlüssel lesbar"),
          "Schlüssel sofort vom Server entfernen, neuen Schlüssel erzeugen und den alten überall aus authorized_keys löschen."),
    Probe("aws", ("/.aws/credentials",), "Cloud-Zugangsdaten (AWS)", "crit",
          _rx(r"aws_access_key_id\s*=", "aws_access_key_id=•••"),
          "Datei entfernen und den Zugangsschlüssel in der AWS-Konsole sofort deaktivieren."),
    Probe("htpasswd", ("/.htpasswd",), "Passwortdatei (.htpasswd)", "crit",
          _rx(r"^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|\$[156]\$)", "Benutzer mit Passwort-Hash lesbar"),
          "Datei aus dem Web-Ordner nehmen und die Passwörter ändern."),
    Probe("wpconfig", ("/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.save", "/wp-config.php.old", "/wp-config.bak"),
          "Sicherungskopie der WordPress-Konfiguration", "crit",
          _rx(r"DB_PASSWORD", "DB_PASSWORD=••• lesbar"),
          "Sicherungskopie löschen und das Datenbank-Passwort sowie die WordPress-Schlüssel (AUTH_KEY …) ändern."),
    Probe("sqldump", ("/backup.sql", "/dump.sql", "/db.sql", "/database.sql", "/backup.zip"), "Datenbank-Sicherung", "crit",
          lambda text, raw: "Datenbank-Dump lesbar (CREATE TABLE / INSERT)" if re.search(r"CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump", text)
          else ("ZIP-Archiv herunterladbar" if raw[:4] == b"PK\x03\x04" else None),
          "Sicherung vom Webserver entfernen. Sie enthält vermutlich Benutzerdaten und Passwort-Hashes: Betroffene informieren und Passwörter ändern."),
    Probe("sftp", ("/sftp-config.json", "/.vscode/sftp.json"), "Zugangsdaten eines Editors (SFTP)", "crit",
          _rx(r'"password"\s*:', '"password": ••• lesbar'),
          "Datei löschen und das SFTP- bzw. SSH-Passwort ändern."),
    Probe("actuator", ("/actuator/env",), "Spring-Boot-Umgebung (Konfiguration und Geheimnisse)", "crit",
          _rx(r'"propertySources"', "Umgebungsvariablen der Anwendung lesbar"),
          "Actuator-Endpunkte nur intern freigeben (management.endpoints.web.exposure.include=health)."),
    Probe("compose", ("/docker-compose.yml", "/docker-compose.yaml", "/compose.yaml"), "Docker-Compose-Datei", "warn",
          lambda text, raw: ("Compose-Datei lesbar" + (" mit Passwörtern" if re.search(r"(?i)(password|secret|token)\s*[:=]", text) else ""))
          if re.search(r"^services:", text, re.M) and re.search(r"image:|build:", text) else None,
          "Datei gehört nicht in den Web-Ordner. Enthaltene Passwörter ändern."),
    Probe("phpinfo", ("/phpinfo.php", "/info.php"), "PHP-Info-Seite", "warn",
          _rx(r"phpinfo\(\)|<title>PHP \d", "phpinfo() verrät Pfade, Versionen und Umgebungsvariablen"),
          "Datei löschen. Sie verrät Angreifern Versionen, Pfade und manchmal Zugangsdaten."),
    Probe("status", ("/server-status", "/nginx_status"), "Server-Statusseite", "warn",
          lambda text, raw: "Apache-Statusseite mit aktuellen Anfragen" if "Apache Server Status" in text
          else ("nginx-Statusseite" if re.search(r"Active connections:\s*\d+", text) else None),
          "Statusseite nur für das Heimnetz erlauben (allow 192.168.0.0/16; deny all;)."),
    Probe("dsstore", ("/.DS_Store",), "macOS-Ordnerdatei (.DS_Store)", "warn",
          lambda text, raw: "Dateiliste des Ordners lesbar" if raw[4:8] == b"Bud1" else None,
          "Datei löschen. Sie verrät die Namen aller Dateien im Ordner."),
    Probe("pma", ("/phpmyadmin/", "/pma/", "/adminer.php"), "Datenbank-Verwaltung öffentlich erreichbar", "warn",
          lambda text, raw: "phpMyAdmin-Anmeldung erreichbar" if re.search(r"phpMyAdmin", text) and re.search(r"pma_username|input_username|login", text, re.I)
          else ("Adminer-Anmeldung erreichbar" if re.search(r"<title>[^<]*Adminer", text) else None),
          "Datenbank-Verwaltung nur aus dem Heimnetz oder per VPN erlauben (Access List im Proxy Manager)."),
]
PROBE_BY_PATH = {p: probe for probe in PROBES for p in probe.paths}
_LOG_KEYWORDS = ["%.env%", "%.git%", "%.ssh%", "%.aws%", "%.ht%", "%wp-%", "%php%", "%actuator%", "%.sql%", "%backup%", "%dump%",
                 "%server-status%", "%nginx_status%", "%config%", "%.DS_Store%", "%cgi-bin%", "%sftp%", "%.vscode%", "%compose%",
                 "%etc/passwd%", "%xmlrpc%", "%boaform%", "%HNAP1%", "%admin%"]


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"(?i)nonce=\"[^\"]*\"|[0-9a-f]{16,}|\d{6,}", "", text)).strip()


def _fingerprint(text: str) -> tuple[str, int]:
    n = _norm(text)
    return hashlib.sha1(n.encode("utf-8", "replace")).hexdigest(), len(n)


def _same_page(a: tuple[str, int] | None, b: tuple[str, int]) -> bool:
    if not a:
        return False
    return a[0] == b[0] or (a[1] > 200 and abs(a[1] - b[1]) <= max(40, a[1] * 0.03))


class Fetcher:
    def __init__(self, client: httpx.Client):
        self.client = client

    def get(self, host: str, path: str) -> dict:
        try:
            with self.client.stream("GET", f"https://{host}{path}") as r:
                raw = b""
                for chunk in r.iter_bytes():
                    raw += chunk
                    if len(raw) >= MAX_BYTES:
                        break
                ctype = r.headers.get("content-type", "")
                return {"status": r.status_code, "raw": raw[:MAX_BYTES], "text": raw[:MAX_BYTES].decode("utf-8", "replace"),
                        "ctype": ctype, "location": r.headers.get("location", "")}
        except httpx.HTTPError as e:
            return {"status": None, "raw": b"", "text": "", "ctype": "", "location": "", "error": e.__class__.__name__}


def verdict(res: dict, probe: Probe | None, baseline: tuple[str, int] | None) -> tuple[str, str]:
    """(Ergebnis, Erklärung). Ergebnis: exposed | unclear | catchall | protected | missing | redirect | error"""
    st = res["status"]
    if st is None:
        return "error", f"Keine Antwort ({res.get('error', 'Fehler')})"
    if st in (401, 403):
        return "protected", f"Zugriff verweigert ({st})"
    if 300 <= st < 400:
        return "redirect", f"Umleitung ({st}) nach {res['location'][:80] or '?'}"
    if st >= 400:
        return "missing", f"Nicht vorhanden ({st})"
    if probe:
        ev = probe.check(res["text"], res["raw"])
        if ev:
            return "exposed", ev
    fp = _fingerprint(res["text"])
    if _same_page(baseline, fp) or not res["raw"].strip():
        return "catchall", "Antwortet mit der normalen Seite der App (nichts verraten)"
    if "html" in res["ctype"].lower() or res["text"].lstrip()[:15].lower().startswith(("<!doctype", "<html")):
        return "catchall", "Liefert eine Webseite der App, keine Datei"
    if probe:
        return "catchall", "Inhalt passt nicht zu einer echten Datei dieser Art"
    return "unclear", f"Liefert {len(res['raw'])} Bytes ({res['ctype'] or 'ohne Typ'}). Bitte selbst ansehen"


def log_hits(db: Session, hosts: list[str] | None = None, days: int = LOG_DAYS) -> list[dict]:
    """Angriffs-Anfragen, die mit 2xx beantwortet wurden, je Host und Pfad."""
    E = AccessEvent
    conds = [E.ts >= datetime.utcnow() - timedelta(days=days), E.status >= 200, E.status < 300,
             or_(*[E.path.like(k) for k in _LOG_KEYWORDS]), func.coalesce(E.user_agent, "").not_like("NetworkHelper-%")]
    if hosts is not None:
        conds.append(E.host.in_(hosts))
    rows = db.execute(select(E.host, E.path, func.count(), func.count(func.distinct(E.ip)), func.max(E.ts), func.max(E.bytes))
                      .where(*conds).group_by(E.host, E.path).order_by(func.count().desc()).limit(3000)).all()
    out = []
    for host, path, n, ips, last, size in rows:
        clean = (path or "").split("?")[0]
        if not SCANNER_RE.search(clean) and clean not in PROBE_BY_PATH:
            continue
        out.append({"host": host, "path": clean, "count": n, "ips": ips, "last": last, "bytes": size})
    merged: dict[tuple, dict] = {}
    for h in out:  # gleiche Pfade mit verschiedenen Parametern zusammenfassen
        k = (h["host"], h["path"])
        if k in merged:
            m = merged[k]
            m["count"] += h["count"]
            m["ips"] = max(m["ips"], h["ips"])
            m["last"] = max(m["last"], h["last"])
        else:
            merged[k] = h
    return sorted(merged.values(), key=lambda h: -h["count"])


def check_host(host: str, extra_paths: list[str], client: httpx.Client | None = None) -> dict:
    own = client is None
    client = client or httpx.Client(timeout=10, verify=False, follow_redirects=False, headers={"User-Agent": USER_AGENT})
    try:
        f = Fetcher(client)
        base = f.get(host, f"/networkhelper-{secrets.token_hex(6)}.env")
        baseline = _fingerprint(base["text"]) if base["status"] and base["status"] < 300 else None
        results = []
        paths = list(PROBE_BY_PATH)
        for p in extra_paths:
            if p not in paths:
                paths.append(p)
        for path in paths:
            probe = PROBE_BY_PATH.get(path)
            res = f.get(host, path)
            v, why = verdict(res, probe, baseline)
            results.append({"path": path, "probe": probe.key if probe else None, "result": v, "detail": why, "status": res["status"]})
            if res["status"] is None and res.get("error") in ("ConnectError", "ConnectTimeout"):
                break  # Host nicht erreichbar: nicht 40-mal warten
        return {"host": host, "catchall": baseline is not None, "results": results,
                "error": None if any(r["status"] for r in results) else (results[0]["detail"] if results else "keine Prüfung")}
    finally:
        if own:
            client.close()


def run(db: Session, hosts: list[str] | None = None) -> dict:
    started = datetime.utcnow()
    all_hosts = [h for h in db.scalars(select(SiteCheck.host).where(SiteCheck.enabled.is_(True)))]
    targets = [h for h in all_hosts if hosts is None or h in hosts]
    hits = log_hits(db, targets)
    extra: dict[str, list[str]] = {}
    for h in hits:
        if len(extra.setdefault(h["host"], [])) < 25 and h["path"] not in PROBE_BY_PATH and ".." not in h["path"]:
            extra[h["host"]].append(h["path"])
    with ThreadPoolExecutor(max_workers=4) as pool:
        checked = list(pool.map(lambda h: check_host(h, extra.get(h, [])), targets))
    now = datetime.utcnow()
    hit_map = {(h["host"], h["path"]): h for h in hits}
    seen_keys = set()
    for hc in checked:
        for r in hc["results"]:
            if r["result"] not in ("exposed", "unclear"):
                continue
            seen_keys.add((hc["host"], r["path"]))
            probe = PROBE_BY_PATH.get(r["path"])
            row = db.scalar(select(Exposure).where(Exposure.host == hc["host"], Exposure.path == r["path"]))
            attacked = hit_map.get((hc["host"], r["path"]))
            new = row is None or row.fixed_at is not None
            if row is None:
                row = Exposure(host=hc["host"], path=r["path"], first_seen=now)
                db.add(row)
            row.kind = probe.key if probe else "other"
            row.label = probe.label if probe else "Unbekannte Datei"
            row.severity = (probe.severity if probe else "warn") if r["result"] == "exposed" else "info"
            row.result = r["result"]
            row.evidence = r["detail"][:300]
            row.last_seen, row.fixed_at = now, None
            row.attacked = attacked["count"] if attacked else 0
            row.attacker_ips = attacked["ips"] if attacked else 0
            if new and r["result"] == "exposed":
                body = f"https://{hc['host']}{r['path']}\nGefunden: {r['detail']}\n"
                if attacked:
                    body += (f"\nAchtung: Diese Adresse wurde in den letzten {LOG_DAYS} Tagen {attacked['count']}× von {attacked['ips']} "
                             "fremden Adressen erfolgreich abgerufen. Gehe davon aus, dass die Inhalte bekannt sind.\n")
                body += f"\nSo behebst du es: {probe.fix if probe else 'Datei vom Server entfernen.'}"
                notify.raise_alert(db, row.severity, "exposure", f"{row.label} öffentlich lesbar: {hc['host']}", body,
                                   dedupe_key=f"exposure:{hc['host']}:{r['path']}", dedupe_hours=24)
    # Was diesmal nicht mehr gefunden wurde, gilt als behoben (nur bei geprüften, erreichbaren Hosts)
    reachable = {hc["host"] for hc in checked if not hc["error"]}
    for row in db.scalars(select(Exposure).where(Exposure.fixed_at.is_(None), Exposure.host.in_(reachable or [""]))):
        if (row.host, row.path) not in seen_keys:
            row.fixed_at = now
    # Zusammenfassung je Host für die Anzeige (ohne Inhalte)
    summary = {"started": started.isoformat(), "finished": now.isoformat(), "probes": len(PROBE_BY_PATH),
               "hosts": {hc["host"]: {"catchall": hc["catchall"], "error": hc["error"],
                                      "counts": _count(hc["results"]), "results": hc["results"]}
                         for hc in checked}}
    state.put(db, "exposure_last", summary, commit=False)
    db.commit()
    return summary


def _count(results: list[dict]) -> dict:
    out: dict[str, int] = {}
    for r in results:
        out[r["result"]] = out.get(r["result"], 0) + 1
    return out


def is_own_check(ip: str, user_agent: str | None, public_ip: str | None) -> bool:
    """Eigene Prüfanfragen nicht als Angriff werten. Nur zusammen mit eigener Adresse, sonst könnte sich ein Angreifer tarnen."""
    if not user_agent or not user_agent.startswith("NetworkHelper-"):
        return False
    return classify(ip) in ("private", "loopback") or (public_ip is not None and ip == public_ip)


def own_public_ip(db: Session) -> str | None:
    return publicip.info(db).get("ip")
