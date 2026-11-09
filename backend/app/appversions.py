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
    path: str | None  # öffentlicher Versions-Endpunkt (None = nur über Container erkennbar)
    detect: Callable[[httpx.Response], str | None | bool] | None  # Version, True = ohne Version, None = nicht diese App
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
_DOCKER_HINT = "{name}: neues Image ziehen und neu starten (docker compose pull && docker compose up -d). Vorher die Release-Hinweise lesen."
CONTAINER_APPS = [
    App("paperless", "Paperless-ngx", "paperless-ngx/paperless-ngx", None, None,
        "Paperless-ngx: Datenbank sichern, dann docker compose pull && docker compose up -d. Paperless sollte nicht öffentlich erreichbar sein."),
    App("adguard", "AdGuard Home", "AdguardTeam/AdGuardHome", None, None, "AdGuard Home: Einstellungen → Allgemein → nach Updates suchen, oder neues Image ziehen."),
    App("portainer", "Portainer", "portainer/portainer", None, None, _DOCKER_HINT.format(name="Portainer") + " Portainer gehört nie ins Internet."),
    App("uptimekuma", "Uptime Kuma", "louislam/uptime-kuma", None, None, _DOCKER_HINT.format(name="Uptime Kuma")),
    App("mealie", "Mealie", "mealie-recipes/mealie", None, None, _DOCKER_HINT.format(name="Mealie")),
    App("n8n", "n8n", "n8n-io/n8n", None, None, _DOCKER_HINT.format(name="n8n")),
    App("frigate", "Frigate", "blakeblackshear/frigate", None, None, _DOCKER_HINT.format(name="Frigate")),
    App("zigbee2mqtt", "Zigbee2MQTT", "Koenkk/zigbee2mqtt", None, None, _DOCKER_HINT.format(name="Zigbee2MQTT")),
    App("openwebui", "Open WebUI", "open-webui/open-webui", None, None, _DOCKER_HINT.format(name="Open WebUI")),
    App("stirlingpdf", "Stirling-PDF", "Stirling-Tools/Stirling-PDF", None, None, _DOCKER_HINT.format(name="Stirling-PDF")),
    App("actual", "Actual Budget", "actualbudget/actual", None, None, _DOCKER_HINT.format(name="Actual Budget")),
    App("syncthing", "Syncthing", "syncthing/syncthing", None, None, _DOCKER_HINT.format(name="Syncthing")),
    App("pihole", "Pi-hole", "pi-hole/docker-pi-hole", None, None, _DOCKER_HINT.format(name="Pi-hole")),
    App("nodered", "Node-RED", "node-red/node-red", None, None, _DOCKER_HINT.format(name="Node-RED")),
    App("mosquitto", "Mosquitto", None, None, None, _DOCKER_HINT.format(name="Mosquitto")),
    App("traefik", "Traefik", "traefik/traefik", None, None, _DOCKER_HINT.format(name="Traefik")),
]
APP_BY_KEY = {a.key: a for a in APPS + CONTAINER_APPS}
NPM_APP = App("npm", "Nginx Proxy Manager", "NginxProxyManager/nginx-proxy-manager", "/api/", lambda r: None,
              "Proxy Manager: im Container docker compose pull && docker compose up -d (Image jc21/nginx-proxy-manager:latest).")


def detect_host(host: str, client: httpx.Client) -> dict | None:
    """Erste passende App für einen Hostnamen."""
    for app in APPS:
        if not app.path:
            continue
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


# Image-Name (ohne Registry und Tag) -> App
IMAGES = [
    (r"(^|/)immich-server$", "immich"), (r"paperless-ngx$", "paperless"), (r"(^|/)vaultwarden/server$|(^|/)vaultwarden$", "vaultwarden"),
    (r"nginx-proxy-manager$", "npm"), (r"home-assistant$", "homeassistant"), (r"(^|/)jellyfin$", "jellyfin"),
    (r"(^|/)nextcloud$", "nextcloud"), (r"grafana/grafana(-oss)?$", "grafana"), (r"adguardhome$", "adguard"),
    (r"portainer/portainer-(ce|ee)$", "portainer"), (r"uptime-kuma$", "uptimekuma"), (r"(^|/)mealie$", "mealie"),
    (r"n8nio/n8n$|n8n-io/n8n$", "n8n"), (r"(^|/)frigate$", "frigate"), (r"zigbee2mqtt$", "zigbee2mqtt"),
    (r"open-webui$", "openwebui"), (r"stirling-pdf$|s-pdf$", "stirlingpdf"), (r"actual-server$", "actual"),
    (r"(^|/)syncthing$", "syncthing"), (r"pihole/pihole$", "pihole"), (r"node-red$", "nodered"),
    (r"eclipse-mosquitto$", "mosquitto"), (r"(^|/)traefik$", "traefik"), (r"audiobookshelf$", "audiobookshelf"),
    (r"(^|/)navidrome$", "navidrome"), (r"(^|/)gitea$", "gitea"), (r"forgejo$", "forgejo"),
]
SEMVER = re.compile(r"^v?\d+\.\d+(\.\d+)?([.-].*)?$")


def image_app(image: str) -> App | None:
    name = image.split("@")[0]
    last = name.rsplit("/", 1)[-1]
    if ":" in last:
        name = name[: name.rfind(":")]
    if name.count("/") >= 2 or ("." in name.split("/")[0] and "/" in name):
        name = name.split("/", 1)[1]  # Registry weglassen (ghcr.io/…, lscr.io/…)
    name = name.lower().removeprefix("linuxserver/")
    for pattern, key in IMAGES:
        if re.search(pattern, name):
            return NPM_APP if key == "npm" else APP_BY_KEY.get(key)
    return None


def container_version(c: dict) -> str | None:
    """Version aus dem OCI-Label, dem Linuxserver-Label oder einem Versions-Tag."""
    v = (c.get("version") or "").strip()
    if v and parse_version(v) and v.lower() not in ("latest", "main", "stable"):
        return v.lstrip("v")
    b = c.get("build_version") or ""
    m = re.search(r"version:-\s*v?([\d.]+)", b)
    if m:
        return m.group(1)
    image = c.get("image") or ""
    last = image.split("@")[0].rsplit("/", 1)[-1]
    tag = last.split(":", 1)[1] if ":" in last else ""
    return tag.lstrip("v").split("-ls")[0] if SEMVER.match(tag) else None


def from_agents(db: Session) -> list[dict]:
    """Bekannte Apps in den Containern, die die Agenten melden."""
    import json
    from .models import Agent
    seen, out = set(), []
    for a in db.scalars(select(Agent).where(Agent.last_seen.is_not(None))):
        try:
            containers = json.loads(a.info or "{}").get("docker") or []
        except ValueError:
            continue
        for c in containers:
            app = image_app(str(c.get("image") or ""))
            if app is None:
                continue
            version = container_version(c)
            key = (app.key, version)
            if key in seen:
                continue
            seen.add(key)
            out.append({"host": f"{a.name} · {c.get('name')}", "source": "container", "app_key": app.key, "version": version,
                        "image": c.get("image")})
    return out


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


def newer_available(r: dict) -> bool:
    v, l = parse_version(r.get("version")), parse_version(r.get("latest"))
    return bool(v and l and _cmp(l, v) > 0)


def notify_results(db: Session, results: list[dict]) -> None:
    """Push nur, wenn die installierte Version bekannte Lücken hat UND es eine neuere Version gibt."""
    for r in results:
        hits = r.get("advisories") or []
        if not hits:
            continue
        worst = "crit" if any(a["severity"] in ("critical", "high") for a in hits) else "warn"
        lines = "\n".join(f"• {a['summary']} ({a['severity']}{', ' + a['cve'] if a.get('cve') else ''}), behoben in {a.get('patched') or '?'}"
                          for a in hits[:5])
        where = r.get("host") or ""
        if newer_available(r):
            notify.raise_alert(db, worst, "apps", f"Update mit Sicherheitskorrektur: {r['name']} {r['version']} → {r['latest']}",
                               f"Läuft auf: {where}\nBekannte Lücken in deiner Version:\n{lines}\n\nSo aktualisierst du: {r['hint']}"
                               + (f"\nVersionshinweise: {r['release_url']}" if r.get("release_url") else ""),
                               dedupe_key=f"app-upd:{r['app']}:{r['version']}:{r.get('latest')}", dedupe_hours=24 * 30)
        else:
            notify.raise_alert(db, "info", "apps", f"{r['name']} {r['version']}: bekannte Lücke, noch kein Update",
                               f"Läuft auf: {where}\n{lines}\n\nSobald es ein Update gibt, kommt eine Push-Nachricht.",
                               dedupe_key=f"app-noupd:{r['app']}:{r['version']}", dedupe_hours=24 * 30)


# ---------- Eigene Apps auf GitHub ----------

def own_repos(db: Session) -> list[dict]:
    """Stand der Sicherheitsprüfung und offene Dependabot-Vorschläge deiner eigenen Repositories."""
    out = []
    for repo in [r.strip() for r in (settings.own_repos or "").split(",") if r.strip()][:15]:
        key = f"gh_own:{repo}"
        cached, at = state.get_with_time(db, key)
        if cached and at and datetime.utcnow() - at < timedelta(hours=CACHE_HOURS):
            out.append(cached)
            continue
        item = {"repo": repo, "url": f"https://github.com/{repo}"}
        try:
            data = _gh(f"/repos/{repo}/actions/workflows/security.yml/runs?branch=main&per_page=1")
            runs = (data.get("workflow_runs") if isinstance(data, dict) else None) or []
            if runs:
                item.update(security=runs[0].get("conclusion") or runs[0].get("status"), security_url=runs[0].get("html_url"),
                            security_at=runs[0].get("updated_at"), run_id=runs[0].get("id"))
            else:
                item["security"] = "none"
            prs = _gh(f"/repos/{repo}/pulls?state=open&per_page=50")
            item["dependabot_open"] = sum(1 for p in prs if isinstance(p, dict) and (p.get("user") or {}).get("login") == "dependabot[bot]")
        except (httpx.HTTPError, ValueError) as e:
            item["error"] = str(e)[:120]
        state.put(db, key, item)
        out.append(item)
        if item.get("security") == "failure":
            notify.raise_alert(db, "warn", "apps", f"Bekannte Lücke in deiner App {repo.split('/')[-1]}",
                               "Die tägliche Sicherheitsprüfung auf GitHub ist rot: In einem Paket gibt es eine Lücke, für die "
                               "Dependabot keine automatische Korrektur übernehmen konnte (oft ein großer Versionssprung).\n"
                               f"Details: {item.get('security_url')}", dedupe_key=f"own-sec:{repo}:{item.get('run_id')}", dedupe_hours=24 * 30)
    return out


def run(db: Session) -> dict:
    hosts = list(db.scalars(select(SiteCheck.host).where(SiteCheck.enabled.is_(True))))
    with httpx.Client(timeout=8, verify=False, follow_redirects=False, headers={"User-Agent": UA}) as client:
        with ThreadPoolExecutor(max_workers=4) as pool:
            found = dict(zip(hosts, pool.map(lambda h: detect_host(h, client), hosts)))
    results = []
    # Container sind die genaueste Quelle (Version aus dem Image)
    containers = from_agents(db)
    for c in containers:
        app = NPM_APP if c["app_key"] == "npm" else APP_BY_KEY[c["app_key"]]
        results.append({"host": c["host"], "source": "container", "image": c["image"], **evaluate(db, app, c["version"])})
    have = {(r["app"], r.get("version")) for r in results}
    for host, f in found.items():
        if not f:
            results.append({"host": host, "app": None, "status": "none", "source": "web"})
            continue
        if f.get("error"):
            results.append({"host": host, "app": None, "status": "error", "error": f["error"], "source": "web"})
            continue
        if (f["app"], f["version"]) in have or (f["version"] is None and any(r["app"] == f["app"] for r in results)):
            for r in results:  # schon über den Container bekannt: nur die Domain dazuschreiben
                if r["app"] == f["app"] and (f["version"] is None or r.get("version") == f["version"]):
                    r["host"] = f"{host} · {r['host']}"
                    break
            continue
        results.append({"host": host, "source": "web", **evaluate(db, APP_BY_KEY[f["app"]], f["version"])})
    if not any(r.get("app") == "npm" for r in results):
        nv = npm_version() if npm.configured() or settings.npm_url else None
        if nv:
            results.append({"host": "Proxy Manager (Verwaltung)", "source": "web", **evaluate(db, NPM_APP, nv)})
    notify_results(db, results)
    summary = {"checked": datetime.utcnow().isoformat(), "items": results, "own": own_repos(db)}
    state.put(db, "appversions", summary)
    return summary
