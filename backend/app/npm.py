"""Nginx Proxy Manager: Proxy Hosts über die eigene API lesen (nur lesend).

Die API liegt auf dem Verwaltungsport (meist 81). Angemeldet wird mit E-Mail und Passwort eines Kontos; am besten
legst du im Proxy Manager ein eigenes Konto an, das nur Proxy Hosts sehen darf.
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
