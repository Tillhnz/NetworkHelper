"""Land und Netzbetreiber zu einer IP-Adresse, offline aus den kostenlosen Datenbanken von DB-IP.

Die Dateien (je rund 10 MB) werden einmal im Monat von download.db-ip.com geladen und im Datenordner gespeichert.
Abfragen laufen danach vollständig lokal, keine IP-Adresse verlässt den Server.
Lizenz: IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0.
"""
from __future__ import annotations

import gzip
import logging
import os
import shutil
import threading
from datetime import date, timedelta
from functools import lru_cache

import httpx

from .config import settings
from .netutil import classify

log = logging.getLogger("networkhelper.geoip")

FILES = {"country": "dbip-country-lite", "asn": "dbip-asn-lite"}
_lock = threading.Lock()
_readers: dict[str, object] = {}


def _path(kind: str) -> str:
    return os.path.join(settings.data_dir, f"{FILES[kind]}.mmdb")


def _open(kind: str):
    path = _path(kind)
    if not os.path.exists(path):
        return None
    try:
        import maxminddb
        return maxminddb.open_database(path)
    except Exception:  # beschädigte Datei: beim nächsten Download ersetzt
        log.exception("GeoIP-Datei %s lässt sich nicht öffnen", path)
        return None


def reload() -> None:
    with _lock:
        for r in _readers.values():
            try:
                r.close()
            except Exception:
                pass
        _readers.clear()
        for kind in FILES:
            r = _open(kind)
            if r is not None:
                _readers[kind] = r
    lookup.cache_clear()


def status() -> dict:
    out = {}
    for kind in FILES:
        p = _path(kind)
        out[kind] = {"present": os.path.exists(p), "modified": os.path.getmtime(p) if os.path.exists(p) else None}
    return out


@lru_cache(maxsize=50000)
def lookup(ip: str) -> tuple[str | None, int | None, str | None]:
    """(Ländercode, ASN, Netzbetreiber). Private Adressen: ('LAN', None, 'Heimnetz')."""
    kind = classify(ip)
    if kind in ("private", "loopback"):
        return None, None, "Heimnetz"
    if kind != "public" or not settings.geoip_enabled:
        return None, None, None
    country = asn = org = None
    c = _readers.get("country")
    if c is not None:
        try:
            rec = c.get(ip) or {}
            country = (rec.get("country") or {}).get("iso_code")
        except Exception:
            pass
    a = _readers.get("asn")
    if a is not None:
        try:
            rec = a.get(ip) or {}
            asn = rec.get("autonomous_system_number")
            org = (rec.get("autonomous_system_organization") or "")[:120] or None
        except Exception:
            pass
    return country, asn, org


def _download(kind: str) -> bool:
    """Lädt die Datei des aktuellen (oder vorigen) Monats. True bei Erfolg."""
    os.makedirs(settings.data_dir, exist_ok=True)
    today = date.today()
    months = [today, today.replace(day=1) - timedelta(days=1)]
    for m in months:
        url = f"https://download.db-ip.com/free/{FILES[kind]}-{m:%Y-%m}.mmdb.gz"
        tmp = _path(kind) + ".part"
        try:
            with httpx.stream("GET", url, timeout=120, follow_redirects=True) as r:
                if r.status_code != 200:
                    continue
                with open(tmp + ".gz", "wb") as f:
                    for chunk in r.iter_bytes(1 << 16):
                        f.write(chunk)
            with gzip.open(tmp + ".gz", "rb") as src, open(tmp, "wb") as dst:
                shutil.copyfileobj(src, dst)
            os.replace(tmp, _path(kind))
            log.info("GeoIP-Datenbank %s (%s) geladen", kind, f"{m:%Y-%m}")
            return True
        except Exception as e:  # Netzwerkfehler: später erneut versuchen
            log.warning("GeoIP-Download %s fehlgeschlagen: %s", url, e)
        finally:
            for p in (tmp, tmp + ".gz"):
                if os.path.exists(p):
                    os.remove(p)
    return False


def refresh_if_old(max_age_days: int = 32) -> None:
    import time
    if not settings.geoip_enabled:
        return
    changed = False
    for kind in FILES:
        p = _path(kind)
        if not os.path.exists(p) or time.time() - os.path.getmtime(p) > max_age_days * 86400:
            changed |= _download(kind)
    if changed or not _readers:
        reload()
