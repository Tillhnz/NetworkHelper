"""Nginx Proxy Manager: Proxy Hosts und Zertifikate über die eigene API.

Die API liegt auf dem Verwaltungsport (meist 81). Angemeldet wird mit E-Mail und Passwort eines Kontos; am besten
legst du im Proxy Manager ein eigenes Konto an. Zum Lesen reicht „Nur ansehen“ für Proxy Hosts und Zertifikate;
für das Erneuern von Zertifikaten braucht das Konto bei Zertifikaten „Verwalten“.
"""
from __future__ import annotations

import threading
import time

import httpx

from .config import settings

_lock = threading.Lock()
_token: dict = {"value": None, "until": 0.0, "for": None}


class NpmError(RuntimeError):
    pass


def configured() -> bool:
    return bool(settings.npm_url and settings.npm_email and settings.npm_password)


def _login() -> str:
    key = (settings.npm_url, settings.npm_email, settings.npm_password)
    with _lock:
        if _token["value"] and _token["for"] == key and time.time() < _token["until"]:
            return _token["value"]
        try:
            r = httpx.post(settings.npm_url.rstrip("/") + "/api/tokens",
                           json={"identity": settings.npm_email, "secret": settings.npm_password}, timeout=15)
        except httpx.HTTPError as e:
            raise NpmError(f"Proxy Manager nicht erreichbar ({e.__class__.__name__}). Stimmt die Adresse mit Port 81?")
        if r.status_code in (400, 401, 403):
            raise NpmError("Anmeldung am Proxy Manager fehlgeschlagen: E-Mail oder Passwort stimmen nicht.")
        if r.status_code != 200:
            raise NpmError(f"Proxy Manager antwortet mit Fehler {r.status_code}")
        tok = r.json().get("token")
        if not tok:
            raise NpmError("Proxy Manager hat kein Token geliefert.")
        _token.update(value=tok, until=time.time() + 3000, **{"for": key})
        return tok


def _api(method: str, path: str, params: dict | None = None, timeout: float = 20) -> object:
    if not configured():
        raise NpmError("Der Proxy Manager ist nicht eingerichtet (Administration → Proxy Manager).")
    tok = _login()
    try:
        r = httpx.request(method, settings.npm_url.rstrip("/") + path, params=params,
                          headers={"Authorization": f"Bearer {tok}"}, timeout=timeout)
    except httpx.HTTPError as e:
        raise NpmError(f"Proxy Manager nicht erreichbar ({e.__class__.__name__})")
    if r.status_code == 401:
        _token["value"] = None
        raise NpmError("Die Anmeldung am Proxy Manager ist abgelaufen, bitte erneut versuchen.")
    if r.status_code == 403:
        raise NpmError("Das Konto im Proxy Manager darf das nicht. Für das Erneuern von Zertifikaten braucht es bei "
                       "„Zertifikate“ das Recht „Verwalten“ (Proxy Manager → Benutzer → Berechtigungen).")
    try:
        data = r.json()
    except ValueError:
        data = None
    if r.status_code >= 400:
        msg = ((data or {}).get("error") or {}).get("message") if isinstance(data, dict) else None
        raise NpmError(msg or f"Proxy Manager antwortet mit Fehler {r.status_code}")
    return data


def raw_proxy_hosts() -> list[dict]:
    """Proxy Hosts mit allen Angaben, die die Fehlersuche braucht."""
    out = []
    for h in _api("GET", "/api/nginx/proxy-hosts", {"expand": "certificate"}) or []:
        meta = h.get("meta") or {}
        cert = h.get("certificate") or {}
        out.append({
            "id": h.get("id"), "domains": [d.lower() for d in h.get("domain_names", [])],
            "scheme": h.get("forward_scheme", "http"), "host": h.get("forward_host"), "port": h.get("forward_port"),
            "enabled": bool(h.get("enabled", 1)), "online": meta.get("nginx_online", True) is not False,
            "nginx_err": meta.get("nginx_err"), "certificate_id": h.get("certificate_id") or None,
            "cert_expires": cert.get("expires_on"), "cert_name": cert.get("nice_name"),
            "ssl_forced": bool(h.get("ssl_forced")), "access_list": bool(h.get("access_list_id")),
            "websockets": bool(h.get("allow_websocket_upgrade")),
        })
    return out


def find_host(hosts: list[dict], name: str) -> dict | None:
    """Proxy Host für einen Namen, auch über Platzhalter (*.example.de)."""
    name = name.lower()
    for h in hosts:
        if name in h["domains"]:
            return h
    for h in hosts:
        for d in h["domains"]:
            if d.startswith("*.") and name.endswith(d[1:]) and name.count(".") == d.count("."):
                return h
    return None


def certificates() -> list[dict]:
    out = []
    for c in _api("GET", "/api/nginx/certificates") or []:
        meta = c.get("meta") or {}
        out.append({"id": c.get("id"), "name": c.get("nice_name") or ", ".join(c.get("domain_names") or []),
                    "domains": [d.lower() for d in c.get("domain_names") or []], "provider": c.get("provider"),
                    "expires_on": c.get("expires_on"), "dns_challenge": bool(meta.get("dns_challenge")),
                    "dns_provider": meta.get("dns_provider")})
    return out


def renew_certificate(cert_id: int) -> dict:
    """Erneuert ein Let's-Encrypt-Zertifikat (kann bis zu zwei Minuten dauern)."""
    return _api("POST", f"/api/nginx/certificates/{int(cert_id)}/renew", timeout=180) or {}


def proxy_hosts() -> list[dict]:
    """Alle Proxy Hosts, vereinfacht."""
    if not configured():
        raise NpmError("Der Proxy Manager ist nicht eingerichtet (Administration → Proxy Manager).")
    tok = _login()
    try:
        r = httpx.get(settings.npm_url.rstrip("/") + "/api/nginx/proxy-hosts", params={"expand": "certificate"},
                      headers={"Authorization": f"Bearer {tok}"}, timeout=20)
    except httpx.HTTPError as e:
        raise NpmError(f"Proxy Manager nicht erreichbar ({e.__class__.__name__})")
    if r.status_code == 401:
        _token["value"] = None
        raise NpmError("Die Anmeldung am Proxy Manager ist abgelaufen, bitte erneut versuchen.")
    if r.status_code != 200:
        raise NpmError(f"Proxy Manager antwortet mit Fehler {r.status_code}")
    out = []
    for h in r.json():
        cert = h.get("certificate") or {}
        out.append({
            "id": h.get("id"),
            "domains": [d.lower() for d in h.get("domain_names", [])],
            "forward": f"{h.get('forward_scheme', 'http')}://{h.get('forward_host')}:{h.get('forward_port')}",
            "enabled": bool(h.get("enabled", 1)),
            "ssl": bool(h.get("certificate_id")),
            "ssl_forced": bool(h.get("ssl_forced")),
            "hsts": bool(h.get("hsts_enabled")),
            "access_list": bool(h.get("access_list_id")),
            "cert_expires": cert.get("expires_on"),
        })
    return out
