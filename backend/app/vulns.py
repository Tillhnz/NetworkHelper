"""Lückenwächter: Pakete deiner Dienste mit Lückendatenbanken abgleichen und betroffene Dienste absichern.

1. Die Agenten melden, was in jedem laufenden Container-Image und auf dem Server installiert ist (Inventur mit Syft,
   sonst nur die Systempakete).
2. NetworkHelper fragt dazu die offene Lückendatenbank OSV.dev ab (bündelt GitHub, PyPI, npm, Go, Debian, Alpine …)
   und die Liste der Lücken, die laut US-Behörde CISA schon aktiv ausgenutzt werden (KEV).
   Für Node.js, Python und PHP selbst prüft er zusätzlich, ob es ein Sicherheitsupdate gibt oder die Version
   keine Updates mehr bekommt.
3. Er ordnet die Pakete deinen Proxy Hosts zu (welche Domain zeigt auf welchen Container).
4. Ist eine Lücke kritisch oder wird schon ausgenutzt und der Dienst ist offen im Internet, schaltet er eine
   Zugriffsliste davor: Der Dienst geht dann nur noch aus dem Heimnetz. Sobald das Paket aktualisiert ist, hebt er
   das von selbst wieder auf.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import cvss, notify, npm, publicip, state
from .config import settings
from .models import Agent, InventoryTarget, Quarantine, Vuln, VulnAction, VulnFinding

log = logging.getLogger("networkhelper.vulns")

OSV = "https://api.osv.dev/v1"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EOL_URL = "https://endoflife.date/api/{}.json"
NODE_INDEX = "https://nodejs.org/dist/index.json"
HOME_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"]
MAX_PACKAGES = 20000
UA = {"User-Agent": "NetworkHelper-Lueckenwaechter"}

# Syft-Pakettyp → OSV-Ökosystem (Systempakete hängen von der Distribution ab)
LANG = {"python": "PyPI", "npm": "npm", "go-module": "Go", "java-archive": "Maven", "gem": "RubyGems",
        "php-composer": "Packagist", "rust-crate": "crates.io", "dotnet": "NuGet", "hex": "Hex", "pub": "Pub"}
LANG_LABEL = {"PyPI": "Python", "npm": "Node.js", "Go": "Go", "Maven": "Java", "RubyGems": "Ruby",
              "Packagist": "PHP", "crates.io": "Rust", "NuGet": ".NET", "Hex": "Elixir", "Pub": "Dart"}
RUNTIMES = {"node": "nodejs", "nodejs": "nodejs", "python": "python", "python3": "python", "php": "php", "php-cli": "php"}


class VulnError(RuntimeError):
    pass


# ---------- Inventur vom Agenten ----------

def _clean_packages(rows) -> list[list[str]]:
    out = []
    for r in (rows or [])[:MAX_PACKAGES]:
        if not isinstance(r, (list, tuple)) or len(r) < 3:
            continue
        typ, name, version = (str(x)[:200] for x in r[:3])
        purl = str(r[3])[:300] if len(r) > 3 and r[3] else ""
        if name and version:
            out.append([typ[:30], name, version, purl] if purl else [typ[:30], name, version])
    return out


def _clean_container(c: dict) -> dict:
    out = {"name": str(c.get("name", ""))[:120], "ports": str(c.get("ports", ""))[:300]}
    comp = c.get("compose")
    if isinstance(comp, dict) and comp.get("project") and comp.get("service"):
        out["compose"] = {k: str(comp.get(k) or "")[:300] for k in ("project", "service", "dir", "files")}
    return out


def ingest(db: Session, agent: Agent, payload: dict) -> dict:
    """Speichert die Inventur eines Agenten. complete=True: Ziele, die fehlen, laufen nicht mehr."""
    now = datetime.utcnow()
    seen = set()
    for t in (payload.get("targets") or [])[:200]:
        key = str(t.get("key") or "")[:120]
        if not re.match(r"^(host|image:[A-Za-z0-9:._-]+)$", key):
            continue
        seen.add(key)
        row = db.scalar(select(InventoryTarget).where(InventoryTarget.agent_id == agent.id, InventoryTarget.key == key))
        if row is None:
            row = InventoryTarget(agent_id=agent.id, key=key)
            db.add(row)
        row.image = (str(t.get("image") or "")[:300]) or None
        row.containers = json.dumps([_clean_container(c) for c in (t.get("containers") or [])[:50] if isinstance(c, dict)])
        row.distro = (str(t.get("distro") or "")[:60]) or None
        row.scanner = (str(t.get("scanner") or "")[:40]) or None
        row.error = (str(t.get("error") or "")[:300]) or None
        if t.get("packages") is not None or not row.packages:
            pk = _clean_packages(t.get("packages"))
            row.packages = json.dumps(pk)
            row.package_count = len(pk)
        row.scanned_at = now
    if payload.get("complete"):
        for row in db.scalars(select(InventoryTarget).where(InventoryTarget.agent_id == agent.id)):
            if row.key not in seen:
                db.delete(row)
    db.commit()
    return {"ok": True, "targets": len(seen)}


# ---------- Abfrage OSV ----------

def ecosystem(typ: str, distro: str | None) -> str | None:
    if typ in LANG:
        return LANG[typ]
    if not distro:
        return None
    dist, _, ver = distro.partition(":")
    if typ == "deb" and dist == "debian" and ver:
        return f"Debian:{ver.split('.')[0]}"
    if typ == "deb" and dist == "ubuntu" and ver:
        major = ver.split(".")[:2]
        v = ".".join(major)
        lts = len(major) == 2 and major[1] == "04" and int(major[0]) % 2 == 0
        return f"Ubuntu:{v}:LTS" if lts else f"Ubuntu:{v}"
    if typ == "apk" and dist == "alpine" and ver:
        return "Alpine:v" + ".".join(ver.split(".")[:2])
    return None


def query_for(pkg: list, distro: str | None) -> tuple[str, str, str] | None:
    typ, name, version = pkg[0], pkg[1], pkg[2]
    eco = ecosystem(typ, distro)
    if not eco:
        return None
    if eco == "Maven":
        m = re.match(r"pkg:maven/([^/]+)/([^@]+)@", pkg[3] if len(pkg) > 3 else "")
        if not m:
            return None
        name = f"{m.group(1)}:{m.group(2)}"
    if eco == "Go":
        version = version.removeprefix("go").removeprefix("v")
        if version.startswith("0.0.0-") or version in ("(devel)", ""):
            return None
    return eco, name, version


def osv_batch(queries: list[tuple[str, str, str]]) -> list[list[dict]]:
    """Fragt OSV in Paketen zu 1000 ab. Ergebnis: je Anfrage die Liste [{id, modified}]."""
    out: list[list[dict]] = []
    for i in range(0, len(queries), 1000):
        chunk = queries[i:i + 1000]
        body = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]}
        try:
            r = httpx.post(f"{OSV}/querybatch", json=body, timeout=60, headers=UA)
            r.raise_for_status()
        except httpx.HTTPError as e:
            raise VulnError(f"Lückendatenbank OSV.dev nicht erreichbar ({e.__class__.__name__})")
        out.extend([(res or {}).get("vulns") or [] for res in r.json().get("results", [])])
    return out


def osv_vuln(vid: str, client: httpx.Client | None = None) -> dict:
    try:
        r = (client or httpx).get(f"{OSV}/vulns/{vid}", timeout=30, headers=UA)
        r.raise_for_status()
    except httpx.HTTPError as e:
        raise VulnError(f"OSV.dev: {vid} nicht abrufbar ({e.__class__.__name__})")
    return r.json()


MAX_FETCH = 3000


def _fetch_many(ids: list[str]) -> list[dict]:
    from concurrent.futures import ThreadPoolExecutor

    if not ids:
        return []
    with httpx.Client(limits=httpx.Limits(max_connections=16)) as client:
        def one(vid):
            try:
                return osv_vuln(vid, client)
            except VulnError as e:
                log.warning("%s", e)
                return None
        with ThreadPoolExecutor(max_workers=16) as pool:
            return [d for d in pool.map(one, ids) if d]


def score_of(v: dict) -> float | None:
    best = None
    for s in v.get("severity") or []:
        sc = cvss.score(str(s.get("score") or ""))
        if sc is not None and (best is None or sc > best):
            best = sc
    for a in v.get("affected") or []:
        for s in a.get("severity") or []:
            sc = cvss.score(str(s.get("score") or ""))
            if sc is not None and (best is None or sc > best):
                best = sc
    if best is None:
        label = str((v.get("database_specific") or {}).get("severity") or "").upper()
        best = cvss.LABEL_SCORE.get(label)
    return best


def _fixed_versions(v: dict) -> dict:
    out: dict[str, list[str]] = {}
    for a in v.get("affected") or []:
        p = a.get("package") or {}
        key = f"{p.get('ecosystem', '')}|{p.get('name', '')}".lower()
        for r in a.get("ranges") or []:
            for ev in r.get("events") or []:
                if ev.get("fixed"):
                    out.setdefault(key, [])
                    if ev["fixed"] not in out[key]:
                        out[key].append(ev["fixed"])
    return out


def _parse_dt(s) -> datetime | None:
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def store_vuln(db: Session, data: dict, kev: set[str]) -> Vuln:
    vid = data["id"]
    row = db.get(Vuln, vid) or Vuln(id=vid)
    aliases = list(dict.fromkeys(data.get("aliases") or []))[:20]
    row.summary = (data.get("summary") or (data.get("details") or "").split("\n")[0])[:500] or None
    row.aliases = json.dumps(aliases)
    row.score = score_of(data)
    row.kev = any(a in kev for a in [vid, *aliases])
    row.published = _parse_dt(data.get("published"))
    refs = [r.get("url") for r in data.get("references") or [] if r.get("type") in ("ADVISORY", "WEB")]
    row.url = (refs[0] if refs else f"https://osv.dev/vulnerability/{vid}")[:300]
    row.affected = json.dumps(_fixed_versions(data))
    row.fetched_at = datetime.utcnow()
    db.merge(row)
    return row


def kev_ids(db: Session) -> set[str]:
    """CVE-Nummern, die laut CISA schon aktiv ausgenutzt werden (einmal am Tag aktualisiert)."""
    cached, at = state.get_with_time(db, "vuln_kev")
    if cached and at and datetime.utcnow() - at < timedelta(hours=20):
        return set(cached)
    try:
        r = httpx.get(KEV_URL, timeout=60, headers=UA)
        r.raise_for_status()
        ids = sorted({v["cveID"] for v in r.json().get("vulnerabilities", []) if v.get("cveID")})
        state.put(db, "vuln_kev", ids, commit=False)
        return set(ids)
    except (httpx.HTTPError, ValueError, KeyError):
        log.warning("KEV-Liste nicht abrufbar, nutze letzte Version")
        return set(cached or [])


# ---------- Laufzeiten (Node.js, Python, PHP) ----------

def _vt(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def _fetch_json(url: str):
    r = httpx.get(url, timeout=30, headers=UA)
    r.raise_for_status()
    return r.json()


def runtime_data(db: Session) -> dict:
    cached, at = state.get_with_time(db, "vuln_runtimes")
    if cached and at and datetime.utcnow() - at < timedelta(hours=12):
        return cached
    data = {}
    for product in ("nodejs", "python", "php"):
        try:
            data[product] = [{"cycle": str(c.get("cycle")), "latest": str(c.get("latest")), "eol": c.get("eol")}
                             for c in _fetch_json(EOL_URL.format(product))]
        except (httpx.HTTPError, ValueError):
            pass
    try:
        data["node_security"] = [r["version"].lstrip("v") for r in _fetch_json(NODE_INDEX) if r.get("security")][:400]
    except (httpx.HTTPError, ValueError, KeyError):
        pass
    if data:
        state.put(db, "vuln_runtimes", data, commit=False)
    return data or (cached or {})


def runtime_issues(product: str, version: str, data: dict, today: str) -> list[dict]:
    """Synthetische „Lücken“ für Laufzeiten: Sicherheitsupdate vorhanden oder Version ohne Updates."""
    v = _vt(version)
    if len(v) < 2:
        return []
    cycles = data.get(product) or []
    cyc = next((c for c in cycles if _vt(c["cycle"]) == v[:len(_vt(c["cycle"]))]), None)
    if cyc is None:
        return []
    name = {"nodejs": "Node.js", "python": "Python", "php": "PHP"}[product]
    out = []
    eol = cyc.get("eol")
    if eol is True or (isinstance(eol, str) and eol <= today):
        out.append({"id": f"EOL-{product}-{cyc['cycle']}", "score": 7.0, "fixed": "einer neueren Hauptversion",
                    "summary": f"{name} {cyc['cycle']} bekommt keine Sicherheitsupdates mehr (Ende: {eol if eol is not True else 'erreicht'})."})
    if product == "nodejs":
        newer_sec = [s for s in data.get("node_security", []) if _vt(s)[:1] == v[:1] and _vt(s) > v]
        if newer_sec:
            out.append({"id": f"RUNTIME-nodejs-{version}", "score": 7.5, "fixed": cyc["latest"],
                        "summary": f"Für Node.js {version} gibt es ein Sicherheitsupdate ({cyc['latest']})."})
    elif _vt(cyc["latest"]) > v:
        out.append({"id": f"RUNTIME-{product}-{version}", "score": 5.0, "fixed": cyc["latest"],
                    "summary": f"{name} {version} ist nicht aktuell ({cyc['latest']}); Patch-Versionen enthalten meist Sicherheitskorrekturen."})
    return out


# ---------- Abgleich ----------

def _cves(v: Vuln) -> set[str]:
    al = json.loads(v.aliases or "[]")
    return {a for a in [v.id, *al] if a.startswith("CVE-")}


def scan(db: Session) -> dict:
    """Gleicht alle Inventuren ab und aktualisiert die Funde. Gibt neue Funde zurück."""
    targets = db.scalars(select(InventoryTarget)).all()
    kev = kev_ids(db)
    rt = runtime_data(db)
    today = datetime.utcnow().strftime("%Y-%m-%d")
    queries: dict[tuple, list] = {}  # (eco, name, version) -> [(target, typ)]
    runtime_rows = []
    for t in targets:
        for p in json.loads(t.packages or "[]"):
            if p[0] == "binary" and p[1].lower() in RUNTIMES:
                runtime_rows.append((t, RUNTIMES[p[1].lower()], p[2]))
                continue
            q = query_for(p, t.distro)
            if q:
                queries.setdefault(q, []).append(t)
    keys = list(queries)
    results = osv_batch(keys) if keys else []

    # Details nachladen (nur neue oder geänderte Einträge)
    need = {}
    for res in results:
        for v in res:
            need[v["id"]] = _parse_dt(v.get("modified"))
    known = {v.id: v for v in db.scalars(select(Vuln).where(Vuln.id.in_(list(need))))} if need else {}
    fetch = []
    for vid, modified in need.items():
        row = known.get(vid)
        if row is None or (modified and row.fetched_at < modified) or row.fetched_at < datetime.utcnow() - timedelta(days=30):
            fetch.append(vid)
        else:
            row.kev = bool(_cves(row) & kev) or row.id in kev
    # neue zuerst, höchstens MAX_FETCH pro Lauf, parallel (sonst dauert es bei Debian-Images Stunden)
    fetch.sort(key=lambda v: v in known)
    for data in _fetch_many(fetch[:MAX_FETCH]):
        store_vuln(db, data, kev)
    db.flush()

    now = datetime.utcnow()
    current: dict[tuple, dict] = {}  # (target_id, vuln_id, package) -> Angaben
    for (eco, name, version), res in zip(keys, results):
        vs = [db.get(Vuln, v["id"]) for v in res]
        vs = [v for v in vs if v is not None]
        # gleiche CVE aus mehreren Quellen (z. B. GHSA und PYSEC) nur einmal zählen, die schwerste behalten
        vs.sort(key=lambda v: (-(v.score or 0), v.id))
        taken: set[str] = set()
        for v in vs:
            ids = _cves(v) or {v.id}
            if ids & taken:
                continue
            taken |= ids
            fixed = json.loads(v.affected or "{}").get(f"{eco}|{name}".lower()) or []
            for t in queries[(eco, name, version)]:
                current[(t.id, v.id, name)] = {"eco": eco, "version": version, "fixed": ", ".join(fixed[:3])[:200] or None}
    for t, product, version in runtime_rows:
        for issue in runtime_issues(product, version, rt, today):
            row = db.get(Vuln, issue["id"]) or Vuln(id=issue["id"])
            row.summary, row.score, row.aliases, row.kev = issue["summary"], issue["score"], "[]", False
            row.url = {"nodejs": "https://nodejs.org/en/about/previous-releases", "python": "https://www.python.org/downloads/",
                       "php": "https://www.php.net/supported-versions.php"}[product]
            row.affected, row.fetched_at = "{}", now
            db.merge(row)
            label = {"nodejs": "Node.js", "python": "Python", "php": "PHP"}[product]
            current[(t.id, issue["id"], label)] = {"eco": "Laufzeit", "version": version, "fixed": issue["fixed"]}
    db.flush()

    new = []
    existing = {(f.target_id, f.vuln_id, f.package): f for f in db.scalars(select(VulnFinding))}
    for key, info in current.items():
        f = existing.get(key)
        if f is None:
            f = VulnFinding(target_id=key[0], vuln_id=key[1], package=key[2], ecosystem=info["eco"],
                            version=info["version"], fixed=info["fixed"], first_seen=now)
            db.add(f)
            new.append(f)
        else:
            f.version, f.fixed = info["version"], info["fixed"]
            if f.resolved_at:
                f.resolved_at, f.notified = None, False
                new.append(f)
    for key, f in existing.items():
        if key not in current and f.resolved_at is None:
            f.resolved_at = now
    db.flush()
    return {"new": new, "targets": len(targets), "queries": len(keys)}


# ---------- Welche Domain zeigt auf welches Ziel? ----------

def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _published(ports: str, port: int) -> bool:
    return bool(re.search(rf":{port}->", ports or ""))


def map_services(db: Session, hosts: list[dict]) -> list[dict]:
    """Ordnet jedem Proxy Host das Inventur-Ziel zu (Container-Image oder Server)."""
    agents = db.scalars(select(Agent)).all()
    targets = db.scalars(select(InventoryTarget)).all()
    by_agent: dict[int, list[InventoryTarget]] = {}
    for t in targets:
        by_agent.setdefault(t.agent_id, []).append(t)
    info = {a.id: json.loads(a.info or "{}") for a in agents}

    def container_target(agent_id, pred):
        for t in by_agent.get(agent_id, []):
            for c in json.loads(t.containers or "[]"):
                if pred(c):
                    return t, c["name"]
        return None, None

    out = []
    for h in hosts:
        fh, fp = str(h.get("host") or "").lower(), int(h.get("port") or 0)
        target, via, agent_name = None, None, None
        for a in agents:
            addrs = set(info[a.id].get("addrs") or []) | ({a.last_ip} if a.last_ip else set())
            names = {n.lower().split(".")[0] for n in (a.name, a.hostname) if n}
            local = fh in ("127.0.0.1", "localhost") and any(t.containers and "nginx-proxy-manager" in (t.image or "") for t in by_agent.get(a.id, []))
            if fh in addrs or fh.split(".")[0] in names or local:
                t, cname = container_target(a.id, lambda c: _published(c.get("ports", ""), fp))
                if t is None:
                    t = next((x for x in by_agent.get(a.id, []) if x.key == "host"), None)
                    via = "Server"
                else:
                    via = f"Container {cname}"
                target, agent_name = t, a.name
                break
            if not _is_ip(fh):
                t, cname = container_target(a.id, lambda c: c["name"].lower() == fh)
                if t is not None:
                    target, via, agent_name = t, f"Container {cname}", a.name
                    break
        out.append({"host": h, "target": target, "via": via, "agent": agent_name})
    return out


def _excluded(domains: list[str]) -> str | None:
    own = (urlparse(settings.public_url).hostname or "").lower()
    excl = {d.strip().lower() for d in (settings.vuln_quarantine_exclude or "").split(",") if d.strip()}
    for d in domains:
        if d == own:
            return "NetworkHelper selbst (sonst kämst du von unterwegs nicht mehr an die Freigabe)"
        if d in excl:
            return "steht auf der Ausnahmeliste"
    return None


# ---------- Quarantäne ----------

def allow_list(db: Session) -> list[str]:
    own = {ip for ip, _s, end in publicip.own_periods(db) if end is None}
    return HOME_NETS + sorted(own)


def quarantine(db: Session, host: dict, findings: list[VulnFinding], reason: str, auto: bool, by: str | None = None) -> Quarantine:
    q = Quarantine(proxy_host_id=host["id"], domains=", ".join(host["domains"])[:500], reason=reason[:2000],
                   finding_ids=json.dumps([f.id for f in findings]), prev_access_list_id=int(host.get("access_list_id") or 0),
                   auto=auto, released_by=None)
    try:
        list_id = npm.quarantine_list(allow_list(db))
        npm.set_access_list(host["id"], list_id)
    except npm.NpmError as e:
        q.error = str(e)[:300]
    db.add(q)
    db.flush()
    return q


def release(db: Session, q: Quarantine, by: str) -> None:
    try:
        npm.set_access_list(q.proxy_host_id, q.prev_access_list_id)
        q.error = None
    except npm.NpmError as e:
        q.error = str(e)[:300]
        raise
    q.released_at = datetime.utcnow()
    q.released_by = by


def active_quarantines(db: Session) -> list[Quarantine]:
    return list(db.scalars(select(Quarantine).where(Quarantine.released_at.is_(None), Quarantine.error.is_(None))))


# ---------- Lücken schließen ----------

SYSTEM_ECO = ("Debian", "Ubuntu", "Alpine")
PINNED_TAG = re.compile(r"^v?\d+\.\d+(\.\d+)?([-.+].*)?$")
LANG_FIX = {
    "PyPI": "pip install -U \"{pkg}>={fixed}\"",
    "npm": "npm install {pkg}@{fixed}",
    "Go": "go get {pkg}@v{fixed} && go mod tidy",
    "Maven": "In pom.xml/build.gradle {pkg} auf {fixed} anheben",
    "RubyGems": "bundle update {pkg}",
    "Packagist": "composer update {pkg}",
    "crates.io": "cargo update -p {pkg}",
    "NuGet": "dotnet add package {pkg} --version {fixed}",
}


def _tag(image: str) -> str:
    last = image.rsplit("/", 1)[-1]
    return last.split(":", 1)[1].split("@")[0] if ":" in last else "latest"


def _own_build(image: str) -> bool:
    """Selbst gebaute Images (z. B. „bikehelper-backend“) haben keinen Registry-Pfad und meist kein Tag."""
    return "/" not in image and ":" not in image and "." not in image


def remedy(target: InventoryTarget, findings: list[VulnFinding], agent: Agent | None) -> dict:
    """Wie lassen sich die offenen Lücken dieses Ziels schließen? Für Menschen (Befehle) und für den Agenten (Aktion)."""
    open_f = [f for f in findings if f.resolved_at is None and not f.accepted]
    can = bool(agent and agent.allow_updates)
    steps, action = [], None
    no_fix = sorted({f.package for f in open_f if not f.fixed})
    if target.key == "host":
        sys_pk = sorted({f.package for f in open_f if f.ecosystem.split(":")[0] in SYSTEM_ECO and f.fixed})
        if sys_pk:
            mgr = "apk" if (target.distro or "").startswith("alpine") else "apt"
            steps.append({"text": f"Systempakete aktualisieren ({', '.join(sys_pk[:8])}{' …' if len(sys_pk) > 8 else ''})",
                          "cmd": "apk upgrade --update-cache" if mgr == "apk" else "apt update && apt full-upgrade -y"})
            action = {"kind": "host_packages", "params": {"packages": sys_pk[:200]},
                      "label": f"Systempakete auf {agent.name if agent else 'Server'} aktualisieren"}
        for f in open_f:
            if f.ecosystem in LANG_FIX and f.fixed:
                fixed = f.fixed.split(",")[0].strip()
                steps.append({"text": f"{f.package} ({LANG_LABEL.get(f.ecosystem)}) auf {fixed} oder neuer", "cmd": LANG_FIX[f.ecosystem].format(pkg=f.package, fixed=fixed)})
        if any(f.ecosystem == "Laufzeit" for f in open_f):
            steps.append({"text": "Laufzeit (Node.js/Python/PHP) über den Paketmanager oder die offizielle Quelle auf die genannte Version bringen", "cmd": None})
    else:
        image = target.image or ""
        cont = json.loads(target.containers or "[]")
        comp = next((c for c in cont if c.get("compose")), None)
        pinned = PINNED_TAG.match(_tag(image)) is not None
        if _own_build(image):
            steps.append({"text": "Selbst gebautes Image: Abhängigkeiten anheben und neu bauen", "cmd": None})
            for f in open_f:
                if f.ecosystem in LANG_FIX and f.fixed:
                    fixed = f.fixed.split(",")[0].strip()
                    steps.append({"text": f"{f.package} auf {fixed} oder neuer (requirements.txt / package.json / go.mod …)", "cmd": LANG_FIX[f.ecosystem].format(pkg=f.package, fixed=fixed)})
            if comp:
                c = comp["compose"]
                steps.append({"text": "Danach neu bauen (holt auch ein aktuelles Basis-Image)",
                              "cmd": f"cd {c['dir'] or '<Projektordner>'} && docker compose build --pull {c['service']} && docker compose up -d {c['service']}"})
        else:
            if pinned:
                steps.append({"text": f"Im Compose-File steht die feste Version „{_tag(image)}“. Trag dort eine neuere Version ein (Versionshinweise des Herstellers), dann:", "cmd": None})
            if comp:
                c = comp["compose"]
                steps.append({"text": "Neues Image holen und Container neu starten",
                              "cmd": f"cd {c['dir'] or '<Projektordner>'} && docker compose pull {c['service']} && docker compose up -d {c['service']}"})
                if not pinned:
                    action = {"kind": "container_update", "params": {"container": comp["name"]},
                              "label": f"{comp['name']}: neues Image holen und neu starten"}
            else:
                steps.append({"text": "Der Container wurde nicht mit Docker Compose gestartet. Image neu ziehen und den Container mit denselben Einstellungen neu erstellen",
                              "cmd": f"docker pull {image}"})
            steps.append({"text": "Hilft das nicht, hat der Hersteller noch kein korrigiertes Image veröffentlicht. Dann die Sperre lassen und später erneut versuchen.", "cmd": None})
    note = (f"Für {', '.join(no_fix[:5])} gibt es noch kein Update." if no_fix else None)
    return {"steps": steps, "action": action if (action and open_f) else None, "can_auto": can and action is not None and bool(open_f),
            "agent_allows": can, "no_fix": note}


def queue_action(db: Session, target: InventoryTarget, action: dict, auto: bool, by: str | None) -> VulnAction:
    a = VulnAction(agent_id=target.agent_id, target_id=target.id, kind=action["kind"], params=json.dumps(action["params"]),
                   label=action["label"][:300], auto=auto, created_by=by)
    db.add(a)
    db.flush()
    return a


def pending_actions(db: Session, agent: Agent) -> list[dict]:
    """Für die Antwort an den Agenten: offene Aktionen (danach „gesendet“)."""
    if not agent.allow_updates:
        return []
    out = []
    stale = datetime.utcnow() - timedelta(hours=2)
    for a in db.scalars(select(VulnAction).where(VulnAction.agent_id == agent.id, VulnAction.status.in_(("queued", "sent")))):
        if a.status == "sent" and a.created_at < stale:
            a.status, a.log, a.finished_at = "failed", "Der Agent hat sich nicht zurückgemeldet.", datetime.utcnow()
            continue
        out.append({"id": a.id, "kind": a.kind, **json.loads(a.params)})
        a.status = "sent" if a.status == "queued" else a.status
    db.commit()
    return out


RESULT_TEXT = {
    "ok": ("info", "Update installiert"), "no_update": ("warn", "Kein Update verfügbar"),
    "rolled_back": ("warn", "Update zurückgenommen"), "failed": ("warn", "Update fehlgeschlagen"),
    "manual": ("warn", "Update nur von Hand möglich"),
}


def action_result(db: Session, agent: Agent, data: dict) -> None:
    a = db.get(VulnAction, int(data.get("id") or 0))
    if a is None or a.agent_id != agent.id:
        return
    status = str(data.get("status") or "")
    if status not in ("running", *RESULT_TEXT):
        return
    a.status, a.log = status, str(data.get("log") or "")[:5000] or a.log
    if status != "running":
        a.finished_at = datetime.utcnow()
        sev, title = RESULT_TEXT[status]
        extra = {"ok": "\nNetworkHelper prüft gleich erneut. Ist die Lücke weg, wird eine Sperre von selbst aufgehoben.",
                 "rolled_back": "\nDer Dienst läuft wieder mit dem alten Image. Bitte die Versionshinweise prüfen."}.get(status, "")
        notify.raise_alert(db, sev, "vuln", f"{title}: {a.label}", (a.log or "")[-1200:] + extra,
                           dedupe_key=f"vuln-action:{a.id}", dedupe_hours=24 * 30, commit=False)
    db.commit()


def auto_fix(db: Session) -> None:
    """Bei kritischen Lücken von selbst ein Update versuchen (einmal pro Tag und Ziel)."""
    if settings.vuln_auto_fix == "off":
        return
    since = datetime.utcnow() - timedelta(hours=24)
    for t in db.scalars(select(InventoryTarget)):
        agent = db.get(Agent, t.agent_id)
        if not (agent and agent.allow_updates):
            continue
        fs = list(db.scalars(select(VulnFinding).where(VulnFinding.target_id == t.id, VulnFinding.resolved_at.is_(None),
                                                       VulnFinding.accepted.is_(False))))
        limit = settings.vuln_cvss_threshold if settings.vuln_auto_fix == "critical" else 7
        trigger = [f for f in fs if (v := db.get(Vuln, f.vuln_id)) and (v.kev or (v.score or 0) >= limit)
                   and not f.vuln_id.startswith(("EOL-",))]
        if not trigger:
            continue
        if t.key == "host" and not any(f.fixed for f in trigger):
            continue
        recent = db.scalar(select(VulnAction.id).where(VulnAction.target_id == t.id, VulnAction.created_at >= since).limit(1))
        if recent:
            continue
        plan = remedy(t, fs, agent)
        if plan["can_auto"]:
            a = queue_action(db, t, plan["action"], auto=True, by="automatisch")
            log.info("Automatisches Update angestoßen: %s", a.label)


# ---------- Hintergrund ----------

def _target_label(t: InventoryTarget) -> str:
    names = [c["name"] for c in json.loads(t.containers or "[]")]
    return ", ".join(names) or (t.image or "Server")


def run(db: Session) -> None:
    if not settings.vuln_watch:
        return
    if not db.scalar(select(InventoryTarget.id).limit(1)):
        return
    try:
        res = scan(db)
    except VulnError as e:
        state.put(db, "vuln_error", {"at": datetime.utcnow().isoformat(), "error": str(e)})
        return
    state.put(db, "vuln_error", None, commit=False)
    state.put(db, "vuln_last_scan", {"at": datetime.utcnow().isoformat(), "targets": res["targets"], "queries": res["queries"]}, commit=False)

    try:
        hosts = [h for h in npm.raw_proxy_hosts() if h["enabled"]] if npm.configured() else []
    except npm.NpmError:
        hosts = []
    services = map_services(db, hosts)
    by_target: dict[int, list[dict]] = {}
    for s in services:
        if s["target"] is not None:
            by_target.setdefault(s["target"].id, []).append(s)

    # automatisch wieder freigeben, wenn alle auslösenden Lücken behoben sind
    for q in active_quarantines(db):
        ids = json.loads(q.finding_ids or "[]")
        fs = [db.get(VulnFinding, i) for i in ids]
        if all(f is None or f.resolved_at or f.accepted for f in fs):
            try:
                release(db, q, "automatisch (Lücke behoben)")
                notify.raise_alert(db, "info", "vuln", f"Wieder erreichbar: {q.domains.split(',')[0]}",
                                   "Die Lücke ist behoben (das Paket wurde aktualisiert). Der Dienst ist wieder aus dem Internet erreichbar.",
                                   dedupe_key=f"vuln-release:{q.id}", dedupe_hours=24 * 30, commit=False)
            except npm.NpmError:
                pass

    released = {}
    for q in db.scalars(select(Quarantine).where(Quarantine.released_at.is_not(None), Quarantine.auto.is_(True))):
        released.setdefault(q.proxy_host_id, set()).update(json.loads(q.finding_ids or "[]"))
    active_hosts = {q.proxy_host_id for q in active_quarantines(db)}

    # neue Funde je Ziel melden
    todo: dict[int, list[VulnFinding]] = {}
    for f in db.scalars(select(VulnFinding).where(VulnFinding.notified.is_(False), VulnFinding.resolved_at.is_(None),
                                                  VulnFinding.accepted.is_(False))):
        todo.setdefault(f.target_id, []).append(f)
    for target_id, fs in todo.items():
        t = db.get(InventoryTarget, target_id)
        vulns = {f.id: db.get(Vuln, f.vuln_id) for f in fs}
        serious = [f for f in fs if vulns[f.id] and (vulns[f.id].kev or (vulns[f.id].score or 0) >= 7)]
        hard = [f for f in fs if vulns[f.id] and (vulns[f.id].kev or (vulns[f.id].score or 0) >= settings.vuln_cvss_threshold)
                and not f.vuln_id.startswith(("RUNTIME-", "EOL-"))]
        for f in fs:
            f.notified = True
        if not serious:
            continue
        svc = by_target.get(target_id, [])
        public = [s for s in svc if not s["host"].get("access_list_id")]
        lines = []
        for f in sorted(serious, key=lambda f: -(vulns[f.id].score or 0))[:8]:
            v = vulns[f.id]
            tag = " · WIRD AUSGENUTZT" if v.kev else ""
            lines.append(f"• {f.package} {f.version}: {v.summary or v.id} ({cvss.label(v.score)}{tag})"
                         + (f" → behoben in {f.fixed}" if f.fixed else " → noch kein Update"))
        where = ", ".join(d for s in svc for d in s["host"]["domains"][:2]) or _target_label(t)
        body = f"Betrifft: {where}\n" + "\n".join(lines)
        locked = []
        if hard and settings.vuln_auto_quarantine and npm.configured():
            for s in public:
                if s["host"]["id"] in active_hosts:
                    continue
                if set(f.id for f in hard) <= released.get(s["host"]["id"], set()):
                    continue  # schon einmal bewusst freigegeben
                why = _excluded(s["host"]["domains"])
                if why:
                    body += f"\nNicht gesperrt: {s['host']['domains'][0]} ({why})."
                    continue
                q = quarantine(db, s["host"], hard, body, auto=True)
                if q.error:
                    body += f"\nSperren fehlgeschlagen für {s['host']['domains'][0]}: {q.error}"
                else:
                    locked.append(s["host"]["domains"][0])
                    active_hosts.add(s["host"]["id"])
        if locked:
            body += ("\n\nVorsichtshalber nur noch aus dem Heimnetz erreichbar: " + ", ".join(locked)
                     + ". Nach dem Update gibt NetworkHelper den Dienst von selbst wieder frei. Freigeben von Hand: Sicherheit → Lücken.")
        elif svc and not public:
            body += "\n\nDer Dienst ist durch eine Zugriffsliste geschützt, deshalb nicht automatisch gesperrt."
        elif not svc:
            body += "\n\nKeine Domain zeigt auf diesen Dienst. Er ist also vermutlich nicht direkt aus dem Internet erreichbar."
        sev = "crit" if locked or (public and hard) else "warn"
        title = (f"Gesperrt wegen Lücke: {', '.join(locked)}" if locked else
                 f"{'Kritische ' if hard else ''}Lücke in {where.split(',')[0]}")
        agent = db.get(Agent, t.agent_id)
        if agent and agent.allow_updates and settings.vuln_auto_fix != "off" and (hard or settings.vuln_auto_fix == "serious"):
            body += "\n\nNetworkHelper versucht jetzt, die Lücke per Update zu schließen, und meldet sich mit dem Ergebnis."
        notify.raise_alert(db, sev, "vuln", title, body, dedupe_key=f"vuln:{target_id}:{','.join(sorted(f.vuln_id for f in serious))}"[:200],
                           dedupe_hours=24 * 7, commit=False)
    auto_fix(db)
    db.commit()


# ---------- Für die Oberfläche ----------

def finding_dict(f: VulnFinding, v: Vuln | None) -> dict:
    return {"id": f.id, "vuln": f.vuln_id, "package": f.package, "version": f.version, "fixed": f.fixed,
            "ecosystem": f.ecosystem, "language": LANG_LABEL.get(f.ecosystem, "System" if ":" in f.ecosystem else f.ecosystem),
            "score": v.score if v else None, "severity": cvss.label(v.score if v else None), "kev": bool(v and v.kev),
            "summary": v.summary if v else None, "url": v.url if v else None,
            "cves": sorted(_cves(v))[:3] if v else [], "first_seen": f.first_seen.isoformat(), "accepted": f.accepted}


def target_findings(db: Session, target_id: int) -> list[dict]:
    rows = list(db.scalars(select(VulnFinding).where(VulnFinding.target_id == target_id, VulnFinding.resolved_at.is_(None))))
    vmap = {v.id: v for v in db.scalars(select(Vuln).where(Vuln.id.in_({f.vuln_id for f in rows})))} if rows else {}
    out = [finding_dict(f, vmap.get(f.vuln_id)) for f in rows]
    return sorted(out, key=lambda x: (not x["kev"], -(x["score"] or 0), x["package"]))[:2000]


def overview(db: Session) -> dict:
    targets = {t.id: t for t in db.scalars(select(InventoryTarget))}
    agents = {a.id: a.name for a in db.scalars(select(Agent))}
    try:
        hosts = [h for h in npm.raw_proxy_hosts() if h["enabled"]] if npm.configured() else []
        npm_error = None
    except npm.NpmError as e:
        hosts, npm_error = [], str(e)
    services = map_services(db, hosts)
    svc_by_target: dict[int, list[dict]] = {}
    for s in services:
        if s["target"] is not None:
            svc_by_target.setdefault(s["target"].id, []).append(
                {"id": s["host"]["id"], "domains": s["host"]["domains"], "via": s["via"], "protected": bool(s["host"].get("access_list_id"))})
    quarantines = {}
    for q in db.scalars(select(Quarantine).order_by(Quarantine.started_at.desc()).limit(200)):
        quarantines.setdefault(q.proxy_host_id, []).append(q)
    open_rows = list(db.scalars(select(VulnFinding).where(VulnFinding.resolved_at.is_(None))))
    vmap = {v.id: v for v in db.scalars(select(Vuln).where(Vuln.id.in_({f.vuln_id for f in open_rows})))} if open_rows else {}
    findings: dict[int, list[dict]] = {}
    minor: dict[int, int] = {}
    for f in open_rows:
        v = vmap.get(f.vuln_id)
        if not (f.accepted or (v and (v.kev or (v.score or 0) >= 7))):
            minor[f.target_id] = minor.get(f.target_id, 0) + 1  # gering/unbekannt: nur zählen, auf Wunsch nachladen
            continue
        findings.setdefault(f.target_id, []).append(finding_dict(f, v))
    agent_rows = {a.id: a for a in db.scalars(select(Agent))}
    finding_rows: dict[int, list[VulnFinding]] = {}
    for f in open_rows:
        finding_rows.setdefault(f.target_id, []).append(f)
    actions: dict[int, list[dict]] = {}
    for a in db.scalars(select(VulnAction).order_by(VulnAction.created_at.desc()).limit(300)):
        actions.setdefault(a.target_id or 0, []).append({
            "id": a.id, "label": a.label, "status": a.status, "log": a.log, "auto": a.auto, "by": a.created_by,
            "created_at": a.created_at.isoformat(), "finished_at": a.finished_at.isoformat() if a.finished_at else None})
    items = []
    for tid, t in targets.items():
        fs = sorted(findings.get(tid, []), key=lambda x: (not x["kev"], -(x["score"] or 0)))
        svcs = svc_by_target.get(tid, [])
        items.append({"id": tid, "agent": agents.get(t.agent_id), "key": t.key, "image": t.image, "label": _target_label(t),
                      "distro": t.distro, "scanner": t.scanner, "packages": t.package_count, "error": t.error,
                      "scanned_at": t.scanned_at.isoformat(), "services": svcs, "findings": fs, "minor": minor.get(tid, 0),
                      "exposed": any(not s["protected"] for s in svcs),
                      "remedy": remedy(t, finding_rows.get(tid, []), agent_rows.get(t.agent_id)) if tid in finding_rows else None,
                      "actions": actions.get(tid, [])[:5]})
    items.sort(key=lambda i: (not i["exposed"], -max([f["score"] or 0 for f in i["findings"] if not f["accepted"]] or [0]), i["label"]))
    unmapped = [{"id": s["host"]["id"], "domains": s["host"]["domains"], "forward": f"{s['host']['host']}:{s['host']['port']}"}
                for s in services if s["target"] is None]
    q_rows = [{"id": q.id, "host_id": q.proxy_host_id, "domains": q.domains, "reason": q.reason, "auto": q.auto,
               "started_at": q.started_at.isoformat(), "released_at": q.released_at.isoformat() if q.released_at else None,
               "released_by": q.released_by, "error": q.error} for qs in quarantines.values() for q in qs]
    return {"enabled": settings.vuln_watch, "auto": settings.vuln_auto_quarantine, "auto_fix": settings.vuln_auto_fix, "threshold": settings.vuln_cvss_threshold,
            "push": notify.push_configured(), "items": items, "unmapped": unmapped, "quarantines": q_rows,
            "npm_error": npm_error, "last_scan": state.get(db, "vuln_last_scan"), "error": state.get(db, "vuln_error")}
