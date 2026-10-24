"""Porkbun-API (v3): DNS-Records lesen, anlegen, ändern und löschen.

Voraussetzungen bei Porkbun: API-Schlüssel unter Account → API Access anlegen und bei jeder Domain unter
„Details“ den Schalter „API Access“ einschalten. Die Schlüssel werden im JSON-Rumpf gesendet.
"""
from __future__ import annotations

import httpx

from .config import settings

RECORD_TYPES = ("A", "AAAA", "CNAME", "TXT", "MX", "CAA", "NS", "SRV", "ALIAS")


class PorkbunError(RuntimeError):
    pass


def configured() -> bool:
    return bool(settings.porkbun_api_key and settings.porkbun_secret_key)


def _post(path: str, body: dict | None = None, timeout: float = 20, base: str | None = None) -> dict:
    if not configured():
        raise PorkbunError("Porkbun ist nicht eingerichtet. Trage API-Schlüssel und Secret unter Administration → DNS ein.")
    payload = {"apikey": settings.porkbun_api_key, "secretapikey": settings.porkbun_secret_key, **(body or {})}
    url = (base or settings.porkbun_api_url).rstrip("/") + path
    try:
        r = httpx.post(url, json=payload, timeout=timeout)
    except httpx.HTTPError as e:
        raise PorkbunError(f"Porkbun ist nicht erreichbar: {e.__class__.__name__}")
    try:
        data = r.json()
    except ValueError:
        raise PorkbunError(f"Porkbun antwortet mit Fehler {r.status_code}")
    if data.get("status") != "SUCCESS":
        msg = data.get("message") or f"Fehler {r.status_code}"
        if "api access" in msg.lower() or "not opted in" in msg.lower():
            msg += " – schalte bei der Domain in Porkbun unter „Details“ den API-Zugriff ein."
        raise PorkbunError(f"Porkbun: {msg}")
    return data


def ping() -> str | None:
    """Prüft die Schlüssel und liefert die öffentliche IPv4-Adresse aus Sicht von Porkbun."""
    base = settings.porkbun_api_url.replace("://api.porkbun.com", "://api-ipv4.porkbun.com")
    try:
        return _post("/ping", base=base).get("yourIp")
    except PorkbunError:
        return _post("/ping").get("yourIp")


def list_domains() -> list[str]:
    """Domains des Kontos (braucht keine eigene Freigabe je Domain)."""
    data = _post("/domain/listAll", {"start": "0"})
    return sorted(d["domain"] for d in data.get("domains", []) if d.get("status", "ACTIVE") == "ACTIVE")


def managed_domains() -> list[str]:
    """Die eingestellten Domains, sonst alle des Kontos."""
    if settings.porkbun_domains.strip():
        return [d.strip() for d in settings.porkbun_domains.split(",") if d.strip()]
    return list_domains()


def records(domain: str) -> list[dict]:
    data = _post(f"/dns/retrieve/{domain}")
    out = []
    for r in data.get("records", []):
        full = r.get("name", "")
        sub = full[: -len(domain)].rstrip(".") if full.endswith(domain) else full
        out.append({
            "id": str(r.get("id")), "name": sub, "fqdn": full, "type": r.get("type"), "content": r.get("content"),
            "ttl": int(r["ttl"]) if str(r.get("ttl", "")).isdigit() else None, "prio": r.get("prio"), "notes": r.get("notes"),
        })
    return out


def create(domain: str, name: str, rtype: str, content: str, ttl: int = 600, notes: str | None = None) -> str:
    body = {"name": name, "type": rtype, "content": content, "ttl": str(ttl)}
    if notes:
        body["notes"] = notes
    return str(_post(f"/dns/create/{domain}", body).get("id"))


def edit(domain: str, record_id: str, name: str, rtype: str, content: str, ttl: int = 600) -> None:
    _post(f"/dns/edit/{domain}/{record_id}", {"name": name, "type": rtype, "content": content, "ttl": str(ttl)})


def edit_by_name_type(domain: str, rtype: str, name: str, content: str, ttl: int = 600) -> None:
    path = f"/dns/editByNameType/{domain}/{rtype}" + (f"/{name}" if name else "")
    _post(path, {"content": content, "ttl": str(ttl)})


def delete(domain: str, record_id: str) -> None:
    _post(f"/dns/delete/{domain}/{record_id}")
