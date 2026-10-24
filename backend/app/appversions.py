"""Sind die Apps hinter deinen Hostnamen aktuell? Erkennt bekannte Apps an öffentlichen Versions-Endpunkten,
vergleicht mit der neuesten Version auf GitHub und mit veröffentlichten Sicherheitswarnungen (GitHub Security Advisories).

Veraltete Apps sind der häufigste echte Einbruchsweg bei Heimservern. Viele Apps verraten ihre Version ohne Anmeldung;
wo das nicht geht (z. B. Home Assistant), wird nur die App erkannt und auf die Update-Anzeige in der App verwiesen.
"""
from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import notify, npm, state
from .config import settings
from .models import SiteCheck

log = logging.getLogger("networkhelper.apps")
UA = "NetworkHelper-Version-Check/1.0"
CACHE_HOURS = 12


def parse_version(v: str | None) -> tuple[int, ...] | None:
    if not v:
        return None
    m = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?", v)
    if not m:
        return None
    return tuple(int(x) for x in m.groups() if x is not None)


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def in_range(version: str, spec: str | None) -> bool:
    """Prüft Bereiche wie '< 1.2.3', '>= 10.9.0, < 10.9.11' oder '<= 2.0'. Leerer Bereich: nicht betroffen."""
    v = parse_version(version)
    if v is None or not spec or not spec.strip():
        return False
    for part in spec.split(","):
        m = re.match(r"\s*(<=|>=|<|>|=|==)?\s*v?([\w.\-+]+)\s*$", part)
        if not m:
            return False
        op, ref = m.group(1) or "=", parse_version(m.group(2))
        if ref is None:
            return False
        c = _cmp(v, ref)
        ok = {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "=": c == 0, "==": c == 0}[op]
        if not ok:
            return False
    return True


# ---------- Erkennung ----------

@dataclass(frozen=True)
class App:
    key: str
    name: str
    repo: str | None  # GitHub-Repository für Releases
    path: str
    detect: Callable[[httpx.Response], str | None | bool]  # Version, True = erkannt ohne Version, None = nicht diese App
    update_hint: str
    advisory_repo: str | None = None
    advisory_package: str | None = None  # nur Warnungen zu diesem Paket (wenn das Repository mehrere enthält)


def _json(r: httpx.Response):
    try:
        return r.json()
    except ValueError:
        return None


def _nextcloud(r):
    d = _json(r)
    return d.get("versionstring") or d.get("version") if isinstance(d, dict) and d.get("productname", "").lower().startswith("nextcloud") else None


def _jellyfin(r):
    d = _json(r)
    return d.get("Version") if isinstance(d, dict) and "jellyfin" in str(d.get("ProductName", "")).lower() else None


def _vaultwarden(r):
    d = _json(r)
    if isinstance(d, dict) and str((d.get("server") or {}).get("name", "")).lower() == "vaultwarden":
        return (d.get("server") or {}).get("version") or True
    return None


def _immich(r):
    d = _json(r)
    if isinstance(d, dict) and {"major", "minor", "patch"} <= set(d):
        return f"{d['major']}.{d['minor']}.{d['patch']}"
    return None


def _gitea(r):
    d = _json(r)
    v = d.get("version") if isinstance(d, dict) and len(d) == 1 else None
    return v if v and "+gitea" not in v and "forgejo" not in v.lower() else None


def _forgejo(r):
    d = _json(r)
    v = d.get("version") if isinstance(d, dict) and len(d) == 1 else None
    return v.split("+")[0] if v and ("+gitea" in v or "forgejo" in v.lower()) else None


def _grafana(r):
    d = _json(r)
    return d.get("version") if isinstance(d, dict) and "database" in d and "version" in d else None


def _audiobookshelf(r):
    d = _json(r)
    return d.get("serverVersion") if isinstance(d, dict) and d.get("app") == "audiobookshelf" else None


def _navidrome(r):
    d = (_json(r) or {}).get("subsonic-response") if isinstance(_json(r), dict) else None
    if isinstance(d, dict) and str(d.get("type", "")).lower() == "navidrome":
        return str(d.get("serverVersion", "")).split(" ")[0] or True
    return None


def _home_assistant(r):
    d = _json(r)
    return True if isinstance(d, dict) and d.get("name") == "Home Assistant" else None


def _proxmox(r):
    return True if "Proxmox Virtual Environment" in r.text[:5000] else None


APPS = [
    App("nextcloud", "Nextcloud", "nextcloud/server", "/status.php", _nextcloud,
        "Nextcloud: Verwaltung → Übersicht zeigt verfügbare Updates. Bei Docker: neues Image ziehen und Container neu starten.",
        advisory_repo="nextcloud/security-advisories"),
    App("jellyfin", "Jellyfin", "jellyfin/jellyfin", "/System/Info/Public", _jellyfin,
        "Jellyfin: Bei Docker das Image jellyfin/jellyfin:latest ziehen und neu starten, im LXC per apt upgrade."),
    App("vaultwarden", "Vaultwarden", "dani-garcia/vaultwarden", "/api/config", _vaultwarden,
        "Vaultwarden: Image vaultwarden/server:latest ziehen und Container neu starten. Vorher Daten sichern."),
    App("immich", "Immich", "immich-app/immich", "/api/server/version", _immich,
        "Immich: Release-Hinweise lesen (manchmal Änderungen an docker-compose.yml nötig), dann docker compose pull && docker compose up -d."),
    App("gitea", "Gitea", "go-gitea/gitea", "/api/v1/version", _gitea, "Gitea: neues Image bzw. neue Binärdatei installieren und neu starten."),
    App("forgejo", "Forgejo", None, "/api/v1/version", _forgejo, "Forgejo: neue Version von codeberg.org/forgejo installieren."),
    App("grafana", "Grafana", "grafana/grafana", "/api/health", _grafana, "Grafana: neues Image ziehen bzw. per apt aktualisieren."),
    App("audiobookshelf", "Audiobookshelf", "advplyr/audiobookshelf", "/status", _audiobookshelf,
        "Audiobookshelf: Image ghcr.io/advplyr/audiobookshelf ziehen und neu starten."),
    App("navidrome", "Navidrome", "navidrome/navidrome", "/rest/ping.view?f=json&v=1.16.1&c=networkhelper", _navidrome,
        "Navidrome: Image deluan/navidrome:latest ziehen und neu starten."),
    App("homeassistant", "Home Assistant", "home-assistant/core", "/manifest.json", _home_assistant,
        "Home Assistant: Einstellungen → System → Updates. Die Version ist ohne Anmeldung nicht ablesbar."),
    App("proxmox", "Proxmox VE", None, "/", _proxmox,
        "Proxmox: Rechenzentrum → Knoten → Updates → Aktualisieren und Upgrade. Proxmox sollte besser gar nicht öffentlich erreichbar sein."),
]
APP_BY_KEY = {a.key: a for a in APPS}
NPM_APP = App("npm", "Nginx Proxy Manager", "NginxProxyManager/nginx-proxy-manager", "/api/", lambda r: None,
              "Proxy Manager: im Container docker compose pull && docker compose up -d (Image jc21/nginx-proxy-manager:latest).")


def detect_host(host: str, client: httpx.Client) -> dict | None:
    """Erste passende App für einen Hostnamen."""
    for app in APPS:
        try:
            r = client.get(f"https://{host}{app.path}")
        except httpx.HTTPError as e:
            if isinstance(e, (httpx.ConnectError, httpx.ConnectTimeout)):
                return {"error": "nicht erreichbar"}
            continue
        if r.status_code >= 400 and app.key not in ("navidrome",):
            continue
        try:
            found = app.detect(r)
        except Exception:  # noqa: BLE001 – fremde Antworten sind unberechenbar
            found = None
        if found:
            return {"app": app.key, "version": found if isinstance(found, str) else None}
    return None


def npm_version() -> str | None:
    if not settings.npm_url:
        return None
    try:
        d = httpx.get(settings.npm_url.rstrip("/") + "/api/", timeout=8).json()
        v = d.get("version") or {}
        return f"{v.get('major')}.{v.get('minor')}.{v.get('revision', v.get('patch', 0))}" if v.get("major") is not None else None
    except (httpx.HTTPError, ValueError, AttributeError):
        return None


# ---------- GitHub ----------

def _gh(path: str):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": UA}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    r = httpx.get(f"https://api.github.com{path}", headers=headers, timeout=15)
    if r.status_code == 200:
        return r.json()
    raise httpx.HTTPStatusError(f"GitHub {r.status_code}", request=r.request, response=r)


def latest_release(db: Session, repo: str) -> dict | None:
    key = f"gh_latest:{repo}"
    cached, at = state.get_with_time(db, key)
    if cached and at and datetime.utcnow() - at < timedelta(hours=CACHE_HOURS):
        return cached
    try:
        d = _gh(f"/repos/{repo}/releases/latest")
        out = {"version": d.get("tag_name"), "url": d.get("html_url"), "published": d.get("published_at")}
    except (httpx.HTTPError, ValueError) as e:
        log.info("Release von %s nicht abrufbar: %s", repo, e)
        return cached
    state.put(db, key, out)
    return out


def advisories(db: Session, repo: str) -> list[dict]:
    key = f"gh_adv:{repo}"
    cached, at = state.get_with_time(db, key)
    if cached is not None and at and datetime.utcnow() - at < timedelta(hours=CACHE_HOURS):
        return cached
    try:
        items = _gh(f"/repos/{repo}/security-advisories?state=published&per_page=100&sort=published&direction=desc")
        out = [{"id": a.get("ghsa_id"), "summary": (a.get("summary") or "")[:200], "severity": a.get("severity") or "unknown",
                "url": a.get("html_url"), "cve": a.get("cve_id"),
                "vulns": [{"package": ((v.get("package") or {}).get("name") or ""), "range": v.get("vulnerable_version_range") or "",
                           "patched": v.get("patched_versions") or ""} for v in (a.get("vulnerabilities") or [])]}
               for a in items if isinstance(a, dict)]
    except (httpx.HTTPError, ValueError) as e:
        log.info("Sicherheitswarnungen von %s nicht abrufbar: %s", repo, e)
        return cached or []
    state.put(db, key, out)
    return out


def affecting(advs: list[dict], version: str, package: str | None = None) -> list[dict]:
    out = []
    for a in advs:
        for v in a["vulns"]:
            if package and package not in v["package"]:
                continue
            if in_range(version, v["range"]):
                out.append({k: a[k] for k in ("id", "summary", "severity", "url", "cve")} | {"patched": v["patched"]})
                break
    return out


def assess(version: str | None, latest: str | None, hits: list[dict]) -> str:
    """current | patch | minor | major | vulnerable | unknown"""
    if hits:
        return "vulnerable"
    v, l = parse_version(version), parse_version(latest)
    if not v or not l:
        return "unknown"
    if _cmp(v, l) >= 0:
        return "current"
    if v[0] != l[0]:
        return "major"
    if len(v) > 1 and len(l) > 1 and v[1] != l[1]:
        return "minor"
    return "patch"


def evaluate(db: Session, app: App, version: str | None) -> dict:
    rel = latest_release(db, app.repo) if app.repo else None
    hits = []
    if version and (app.advisory_repo or app.repo):
        hits = affecting(advisories(db, app.advisory_repo or app.repo), version, app.advisory_package)
    return {"app": app.key, "name": app.name, "version": version, "latest": (rel or {}).get("version"),
            "release_url": (rel or {}).get("url"), "status": assess(version, (rel or {}).get("version"), hits),
            "advisories": hits[:10], "hint": app.update_hint}


def run(db: Session) -> dict:
    hosts = list(db.scalars(select(SiteCheck.host).where(SiteCheck.enabled.is_(True))))
    with httpx.Client(timeout=8, verify=False, follow_redirects=False, headers={"User-Agent": UA}) as client:
        with ThreadPoolExecutor(max_workers=4) as pool:
            found = dict(zip(hosts, pool.map(lambda h: detect_host(h, client), hosts)))
    results = []
    for host, f in found.items():
        if not f:
            results.append({"host": host, "app": None, "status": "none"})
            continue
        if f.get("error"):
            results.append({"host": host, "app": None, "status": "error", "error": f["error"]})
            continue
        results.append({"host": host, **evaluate(db, APP_BY_KEY[f["app"]], f["version"])})
    nv = npm_version() if npm.configured() or settings.npm_url else None
    if nv:
        results.append({"host": "Proxy Manager (Verwaltung)", **evaluate(db, NPM_APP, nv)})
    now = datetime.utcnow()
    for r in results:
        for a in r.get("advisories") or []:
            sev = "crit" if a["severity"] in ("critical", "high") else "warn"
            notify.raise_alert(db, sev, "apps", f"{r['name']} {r['version']} hat eine bekannte Sicherheitslücke ({r['host']})",
                               f"{a['summary']}\nSchweregrad: {a['severity']}{', ' + a['cve'] if a.get('cve') else ''}\n"
                               f"Behoben in: {a.get('patched') or 'siehe Hinweis'}\n{a['url']}\n\nSo aktualisierst du: {r['hint']}",
                               dedupe_key=f"app-adv:{r['host']}:{a['id']}", dedupe_hours=24 * 7)
    summary = {"checked": now.isoformat(), "items": results}
    state.put(db, "appversions", summary)
    return summary
