"""Zertifikate und Sicherheits-Header je Hostname prüfen und benoten (A bis F)."""
from __future__ import annotations

import json
import logging
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import notify
from .models import SiteCheck

log = logging.getLogger("networkhelper.sites")

PENALTY = {
    "cert_valid": 60, "cert_days": 40, "tls_version": 30, "redirect": 15, "hsts": 10,
    "nosniff": 5, "frame": 5, "csp": 5, "referrer": 3, "server_leak": 2,
}


def grade_for(score: int) -> str:
    for g, lo in (("A", 90), ("B", 80), ("C", 65), ("D", 50), ("E", 35)):
        if score >= lo:
            return g
    return "F"


def _cert_info(host: str, port: int = 443, timeout: float = 8) -> dict:
    """Zertifikat lesen: erst mit Prüfung, bei Fehler ohne, damit Ablaufdatum und Aussteller trotzdem sichtbar sind."""
    out = {"valid": False, "error": None, "expires": None, "issuer": None, "version": None}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                out["version"] = tls.version()
                out["valid"] = True
                out["expires"] = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                out["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
                return out
    except ssl.SSLCertVerificationError as e:
        out["error"] = (e.verify_message or str(e))[:200]
    except (OSError, ssl.SSLError) as e:
        out["error"] = f"Keine TLS-Verbindung: {e.__class__.__name__}"
        return out
    # Ungültiges Zertifikat: ohne Prüfung lesen
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        from cryptography import x509
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                out["version"] = tls.version()
        cert = x509.load_der_x509_certificate(der)
        out["expires"] = cert.not_valid_after_utc.replace(tzinfo=None)
        orgs = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME) or cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        out["issuer"] = orgs[0].value if orgs else None
    except Exception:  # noqa: BLE001 – Anzeige bleibt dann leer
        pass
    return out


def check_host(host: str) -> dict:
    checks = []

    def add(key, label, ok, detail=""):
        checks.append({"key": key, "label": label, "ok": bool(ok), "detail": detail})

    cert = _cert_info(host)
    result = {"cert_valid": cert["valid"], "cert_expires": cert["expires"], "cert_issuer": cert["issuer"],
              "tls_version": cert["version"], "https_redirect": None, "status": None, "error": None}
    if cert["error"] and not cert["expires"]:
        result["error"] = cert["error"]
    add("cert_valid", "Zertifikat gültig", cert["valid"], cert["error"] or (cert["issuer"] or ""))
    if cert["expires"]:
        days = (cert["expires"] - datetime.now(timezone.utc).replace(tzinfo=None)).days
        add("cert_days", "Zertifikat läuft nicht bald ab", days >= 14, f"noch {days} Tage" if days >= 0 else "abgelaufen")
    if cert["version"]:
        add("tls_version", "TLS 1.2 oder neuer", cert["version"] in ("TLSv1.2", "TLSv1.3"), cert["version"])

    # HTTP -> HTTPS
    try:
        r = httpx.get(f"http://{host}/", follow_redirects=False, timeout=10)
        loc = r.headers.get("location", "")
        result["https_redirect"] = r.status_code in (301, 302, 307, 308) and loc.lower().startswith("https://")
        add("redirect", "HTTP leitet auf HTTPS um", result["https_redirect"], f"{r.status_code} {loc[:80]}".strip())
    except httpx.HTTPError as e:
        add("redirect", "HTTP leitet auf HTTPS um", True, f"Port 80 nicht erreichbar ({e.__class__.__name__})")

    # Sicherheits-Header der HTTPS-Antwort
    try:
        r = httpx.get(f"https://{host}/", follow_redirects=True, timeout=12, verify=cert["valid"], max_redirects=5)
        h = {k.lower(): v for k, v in r.headers.items()}
        result["status"] = r.status_code
        hsts = h.get("strict-transport-security", "")
        m = re.search(r"max-age=(\d+)", hsts)
        add("hsts", "HSTS gesetzt (mind. 6 Monate)", bool(m and int(m.group(1)) >= 15552000), hsts[:80] or "fehlt")
        add("nosniff", "X-Content-Type-Options: nosniff", h.get("x-content-type-options", "").lower() == "nosniff", h.get("x-content-type-options", "fehlt"))
        csp = h.get("content-security-policy", "")
        frame_ok = h.get("x-frame-options", "").upper() in ("DENY", "SAMEORIGIN") or "frame-ancestors" in csp
        add("frame", "Schutz vor Einbettung (Clickjacking)", frame_ok, h.get("x-frame-options", "") or ("CSP frame-ancestors" if frame_ok else "fehlt"))
        add("csp", "Content-Security-Policy", bool(csp), (csp[:80] + "…") if len(csp) > 80 else (csp or "fehlt"))
        add("referrer", "Referrer-Policy", bool(h.get("referrer-policy")), h.get("referrer-policy", "fehlt"))
        server = h.get("server", "") + " " + h.get("x-powered-by", "")
        leak = bool(re.search(r"\d+\.\d+", server))
        add("server_leak", "Server verrät keine Versionsnummer", not leak, server.strip() or "keine Angabe")
    except httpx.HTTPError as e:
        result["error"] = result["error"] or f"HTTPS nicht erreichbar: {e.__class__.__name__}"

    score = 100 - sum(PENALTY.get(c["key"], 0) for c in checks if not c["ok"])
    if result["error"] and not cert["expires"]:
        score = 0
    result["score"] = max(0, score)
    result["grade"] = grade_for(result["score"])
    result["checks"] = checks
    return result


def run(db: Session, hosts: list[str] | None = None) -> int:
    rows = db.scalars(select(SiteCheck).where(SiteCheck.enabled.is_(True))).all()
    if hosts is not None:
        rows = [r for r in rows if r.host in hosts]
    if not rows:
        return 0
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = dict(zip([r.host for r in rows], pool.map(check_host, [r.host for r in rows])))
    now = datetime.utcnow()
    for row in rows:
        res = results[row.host]
        row.checked_at = now
        for k in ("grade", "score", "cert_expires", "cert_issuer", "cert_valid", "tls_version", "https_redirect", "status", "error"):
            setattr(row, k, res[k])
        row.checks = json.dumps(res["checks"])
        if res["cert_expires"]:
            days = (res["cert_expires"] - now).days
            if not res["cert_valid"]:
                notify.raise_alert(db, "crit", "cert", f"Ungültiges Zertifikat: {row.host}", next((c["detail"] for c in res["checks"] if c["key"] == "cert_valid"), ""),
                                   dedupe_key=f"cert-invalid:{row.host}", dedupe_hours=24)
            elif days < 5:
                notify.raise_alert(db, "crit", "cert", f"Zertifikat von {row.host} läuft in {max(days, 0)} Tagen ab",
                                   "Prüfe die automatische Erneuerung im Proxy Manager (SSL Certificates).", dedupe_key=f"cert-days:{row.host}:crit", dedupe_hours=24)
            elif days < 14:
                notify.raise_alert(db, "warn", "cert", f"Zertifikat von {row.host} läuft in {days} Tagen ab",
                                   "Let's Encrypt erneuert normalerweise 30 Tage vorher. Läuft die Erneuerung?", dedupe_key=f"cert-days:{row.host}:warn", dedupe_hours=72)
    db.commit()
    return len(rows)
