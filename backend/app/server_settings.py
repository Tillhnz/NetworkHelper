"""Servereinstellungen, die der Administrator in der Oberfläche ändert.

Die Umgebungsvariablen (.env) liefern die Startwerte. Was der Administrator speichert, steht in der Tabelle
app_settings und überschreibt sie. Geheimnisse (Passwörter, API-Schlüssel) werden nie an den Browser zurückgegeben;
dort steht nur, ob ein Wert gesetzt ist.
"""
from __future__ import annotations

import ipaddress
import re
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session

from .config import settings
from .models import AppSetting

# key -> (Typ, Gruppe, Geheimnis?)
FIELDS: dict[str, tuple[str, str, bool]] = {
    "allow_registration": ("bool", "access", False),
    "token_expire_days": ("int:1:90", "access", False),
    "trusted_proxies": ("int:0:5", "access", False),
    "public_url": ("url", "general", False),
    "timezone": ("tz", "general", False),
    "router_type": ("choice:fritzbox|other", "general", False),
    "retention_days": ("int:1:400", "general", False),
    "geoip_enabled": ("bool", "general", False),
    "smtp_host": ("host", "email", False),
    "smtp_port": ("int:1:65535", "email", False),
    "smtp_user": ("str:255", "email", False),
    "smtp_password": ("str:255", "email", True),
    "smtp_from": ("str:255", "email", False),
    "smtp_starttls": ("bool", "email", False),
    "alert_min_severity": ("choice:info|warn|crit", "email", False),
    "porkbun_api_key": ("str:128", "dns", True),
    "porkbun_secret_key": ("str:128", "dns", True),
    "porkbun_domains": ("domains", "dns", False),
    "dyndns_enabled": ("bool", "dns", False),
    "dyndns_interval_min": ("int:1:1440", "dns", False),
    "dns_new_record_type": ("choice:A|CNAME", "dns", False),
    "public_ip_override": ("ipv4opt", "dns", False),
    "npm_url": ("urlopt", "npm", False),
    "npm_email": ("str:255", "npm", False),
    "npm_password": ("str:255", "npm", True),
    "npm_auto_dns": ("bool", "npm", False),
    "npm_auto_monitors": ("bool", "npm", False),
    "scan_enabled": ("bool", "security", False),
    "scan_interval_h": ("int:1:168", "security", False),
    "scan_ports": ("ports", "security", False),
    "scan_targets": ("hosts", "security", False),
    "shodan_enabled": ("bool", "security", False),
    "detect_enabled": ("bool", "security", False),
    "auto_block": ("bool", "security", False),
    "auto_block_hours": ("int:1:8760", "security", False),
    "site_check_interval_h": ("int:1:168", "security", False),
    "monitor_interval_s": ("int:20:3600", "security", False),
}
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$")
DOMAIN_RE = re.compile(r"^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class SettingError(ValueError):
    pass


def _split(text: str) -> list[str]:
    return [p for p in re.split(r"[\s,;]+", text) if p]


def parse_ports(text: str) -> list[int]:
    """'22, 80-90, 443' -> sortierte Liste. Wirft SettingError bei Unsinn."""
    out: set[int] = set()
    for part in _split(text):
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", part)
        if not m:
            raise SettingError(f"„{part}“ ist kein Port oder Bereich")
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (1 <= lo <= hi <= 65535) or hi - lo > 5000:
            raise SettingError(f"„{part}“ liegt außerhalb von 1 bis 65535 oder ist zu groß")
        out.update(range(lo, hi + 1))
    if len(out) > 10000:
        raise SettingError("Höchstens 10.000 Ports")
    return sorted(out)


def coerce(key: str, raw):
    """Prüft einen Wert und gibt ihn im richtigen Typ zurück."""
    kind = FIELDS[key][0]
    base, *args = kind.split(":")
    if base == "bool":
        if isinstance(raw, bool):
            return raw
        if str(raw).lower() in ("true", "1", "yes", "ja"):
            return True
        if str(raw).lower() in ("false", "0", "no", "nein", ""):
            return False
        raise SettingError("Ja oder Nein erwartet")
    if base == "int":
        try:
            n = int(str(raw).strip())
        except ValueError:
            raise SettingError("Ganze Zahl erwartet")
        lo, hi = int(args[0]), int(args[1])
        if not lo <= n <= hi:
            raise SettingError(f"Wert zwischen {lo} und {hi} erwartet")
        return n
    text = str(raw if raw is not None else "").strip()
    if base == "str":
        if len(text) > int(args[0]):
            raise SettingError("Zu lang")
        return text
    if base == "choice":
        options = args[0].split("|")
        if text not in options:
            raise SettingError("Erlaubt: " + ", ".join(options))
        return text
    if base == "host":
        if text and not HOST_RE.match(text):
            raise SettingError("Ungültiger Servername")
        return text
    if base in ("url", "urlopt"):
        if base == "urlopt" and not text:
            return ""
        if not re.match(r"^https?://[^\s]+$", text) or len(text) > 500:
            raise SettingError("Eine Adresse mit http:// oder https:// erwartet")
        return text.rstrip("/")
    if base == "tz":
        try:
            ZoneInfo(text)
        except Exception:
            raise SettingError("Unbekannte Zeitzone (z. B. Europe/Berlin)")
        return text
    if base == "ipv4opt":
        if not text:
            return ""
        try:
            ip = ipaddress.IPv4Address(text)
        except ValueError:
            raise SettingError("Eine IPv4-Adresse erwartet")
        return str(ip)
    if base == "ports":
        parse_ports(text)
        return ", ".join(_split(text))
    if base == "domains":
        items = [d.lower().rstrip(".") for d in _split(text)]
        bad = [d for d in items if not DOMAIN_RE.match(d)]
        if bad:
            raise SettingError(f"Keine gültige Domain: {bad[0]}")
        return ", ".join(dict.fromkeys(items))
    if base == "hosts":
        items = _split(text)
        for h in items:
            try:
                ipaddress.ip_address(h)
            except ValueError:
                if not HOST_RE.match(h):
                    raise SettingError(f"Kein gültiger Hostname: {h}")
        if len(items) > 50:
            raise SettingError("Höchstens 50 Ziele")
        return ", ".join(dict.fromkeys(items))
    raise SettingError("Unbekanntes Feld")


def _serialize(value) -> str:
    return "true" if value is True else "false" if value is False else str(value)


def apply_overrides(db: Session) -> None:
    """Liest die gespeicherten Einstellungen und setzt sie für den laufenden Prozess."""
    for row in db.query(AppSetting).all():
        if row.key in FIELDS:
            try:
                setattr(settings, row.key, coerce(row.key, row.value))
            except SettingError:
                continue


def save(db: Session, values: dict) -> list[str]:
    """Speichert Änderungen. Gibt die geänderten Schlüssel zurück. Geheimnisse: None = behalten, "" = löschen."""
    clean: dict = {}
    errors = {}
    for key, raw in values.items():
        if key not in FIELDS:
            errors[key] = "Unbekannte Einstellung"
            continue
        if FIELDS[key][2] and raw is None:
            continue
        try:
            clean[key] = coerce(key, raw)
        except SettingError as e:
            errors[key] = str(e)
    if errors:
        raise SettingError("; ".join(f"{k}: {v}" for k, v in errors.items()))
    for key, value in clean.items():
        row = db.get(AppSetting, key)
        if row is None:
            db.add(AppSetting(key=key, value=_serialize(value)))
        else:
            row.value = _serialize(value)
        setattr(settings, key, value)
    db.commit()
    return list(clean)


def describe(db: Session) -> dict:
    """Aktuelle Werte für die Oberfläche; Geheimnisse nur als gesetzt/nicht gesetzt."""
    saved = {r.key for r in db.query(AppSetting).all()}
    out = {}
    for key, (kind, group, secret) in FIELDS.items():
        value = getattr(settings, key)
        out[key] = {
            "group": group, "secret": secret, "from_ui": key in saved,
            **({"set": bool(str(value).strip())} if secret else {"value": value}),
        }
    return out
