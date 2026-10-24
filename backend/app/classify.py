"""Warum greift eine Adresse zu? Ordnet jede IP einer verständlichen Ursache zu, mit Begründung.

Grundlage sind die Zugriffe der Adresse im gewählten Zeitraum (Programm, Pfade, Antworten), der Netzbetreiber,
erkannte Vorfälle und die eigene öffentliche IP. Die Regeln sind bewusst einfach und nachvollziehbar; jede
Zuordnung nennt die Hinweise, auf denen sie beruht.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from .detect import SCANNER_RE
from .models import AccessEvent, Incident
from .netutil import classify as ip_scope

# Kategorie -> (Bezeichnung, Gruppe, Kurzbeschreibung)
# Gruppen: friendly (du und deine Nutzer), service (nützliche Dienste), noise (automatisch, meist harmlos), attack
CATEGORIES = {
    "home": ("Dein Heimnetz", "friendly", "Geräte in deinem eigenen Netz"),
    "self": ("Du selbst über deine Domain", "friendly", "Aufrufe von zu Hause über deine Domain: Sie gehen über deine öffentliche IP raus und wieder rein"),
    "app": ("Apps deiner Nutzer", "friendly", "Apps wie Nextcloud, Jellyfin oder Home Assistant, meist vom Handy unterwegs"),
    "visitor": ("Besuche mit dem Browser", "friendly", "Normale Seitenaufrufe aus einem Internetanschluss oder Mobilfunknetz"),
    "acme": ("Let's Encrypt", "service", "Prüft deine Domain, damit das HTTPS-Zertifikat erneuert werden kann"),
    "monitor": ("Erreichbarkeits-Prüfer", "service", "Dienste, die regelmäßig schauen, ob deine Seiten laufen"),
    "crawler": ("Suchmaschinen und KI-Crawler", "service", "Lesen öffentliche Seiten, um sie in Suchergebnisse oder KI-Modelle aufzunehmen"),
    "preview": ("Link-Vorschauen", "service", "Jemand hat einen Link geteilt, und WhatsApp, Telegram & Co. holen Titel und Vorschaubild"),
    "research": ("Internet-Vermessung", "noise", "Firmen wie Censys oder Shodan scannen das ganze Internet. Harmlos, zeigt aber: dein Server ist sichtbar"),
    "datacenter": ("Automatisiert aus Rechenzentren", "noise", "Programme auf Servern in Rechenzentren, oft Bots ohne bösen Zweck, aber unbekannt"),
    "probe": ("Herumstochern", "noise", "Ruft vor allem Seiten auf, die es nicht gibt"),
    "unknown": ("Nicht eindeutig", "noise", "Zu wenig Hinweise für eine sichere Zuordnung"),
    "scan_attack": ("Suche nach Schwachstellen", "attack", "Klopft gezielt an typische Schwachstellen wie /.env oder /wp-login.php"),
    "bruteforce": ("Passwort-Angriffe", "attack", "Probiert in kurzer Zeit viele Anmeldungen aus"),
}
GROUPS = {
    "friendly": "Du und deine Nutzer",
    "service": "Nützliche Dienste",
    "noise": "Automatisch, meist harmlos",
    "attack": "Angriffsversuche",
}

# (Muster im User-Agent, Name)
_RESEARCH = [(r"censys", "Censys"), (r"shodan", "Shodan"), (r"binaryedge", "BinaryEdge"), (r"expanse|paloaltonetworks", "Palo Alto Expanse"),
             (r"internet-measurement|driftnet", "Driftnet"), (r"onyphe", "ONYPHE"), (r"leakix|l9explore|l9tcpid", "LeakIX"),
             (r"stretchoid", "Stretchoid"), (r"criminalip", "Criminal IP"), (r"netcraft", "Netcraft"), (r"modat", "Modat"),
             (r"internettl|internet census", "Internet Census"), (r"visionheight", "Visionheight")]
_RESEARCH_ORG = [(r"censys", "Censys"), (r"shodan", "Shodan"), (r"palo alto", "Palo Alto Expanse"), (r"binaryedge", "BinaryEdge"),
                 (r"onyphe", "ONYPHE"), (r"stretchoid", "Stretchoid"), (r"driftnet", "Driftnet"), (r"modat", "Modat"),
                 (r"internet measurement", "Internet Measurement")]
_MONITOR = [(r"uptimerobot", "UptimeRobot"), (r"better ?uptime|betterstack", "Better Stack"), (r"pingdom", "Pingdom"),
            (r"statuscake", "StatusCake"), (r"uptime-?kuma", "Uptime Kuma"), (r"freshping", "Freshping"), (r"hetrix", "HetrixTools"),
            (r"site24x7", "Site24x7"), (r"networkhelper-", "NetworkHelper (diese App)"), (r"healthchecks", "Healthchecks"),
            (r"gatus", "Gatus"), (r"checkly", "Checkly")]
_CRAWLER = [(r"googlebot|google-inspectiontool|storebot-google|adsbot-google", "Google"), (r"bingbot|bingpreview", "Bing"),
            (r"applebot", "Apple"), (r"duckduckbot|duckassistbot", "DuckDuckGo"), (r"yandex", "Yandex"), (r"baiduspider", "Baidu"),
            (r"petalbot", "Huawei Petal"), (r"ahrefsbot", "Ahrefs"), (r"semrushbot", "Semrush"), (r"mj12bot", "Majestic"),
            (r"dotbot", "Moz"), (r"gptbot|oai-searchbot|chatgpt-user", "OpenAI"), (r"claudebot|claude-web|anthropic", "Anthropic"),
            (r"ccbot", "Common Crawl"), (r"bytespider", "ByteDance"), (r"amazonbot", "Amazon"), (r"perplexitybot", "Perplexity"),
            (r"meta-externalagent|facebookbot", "Meta"), (r"seznambot", "Seznam"), (r"qwantify|qwantbot", "Qwant"),
            (r"dataforseobot", "DataForSEO"), (r"barkrowler", "Babbar"), (r"blexbot", "BLEXBot")]
_PREVIEW = [(r"whatsapp", "WhatsApp"), (r"telegrambot", "Telegram"), (r"slackbot|slack-imgproxy", "Slack"), (r"discordbot", "Discord"),
            (r"facebookexternalhit|facebookcatalog", "Facebook/Instagram"), (r"twitterbot", "X/Twitter"), (r"linkedinbot", "LinkedIn"),
            (r"skypeuripreview", "Skype/Teams"), (r"mastodon", "Mastodon"), (r"signal", "Signal"), (r"iframely", "Iframely"),
            (r"embedly", "Embedly"), (r"redditbot", "Reddit"), (r"matrix|synapse", "Matrix"), (r"pinterestbot", "Pinterest")]
_APP = [(r"nextcloud|owncloud|mirall", "Nextcloud"), (r"jellyfin|finamp|swiftfin|streamyfin", "Jellyfin"), (r"home ?assistant|homeassistant", "Home Assistant"),
        (r"davx5|dav5x|davdroid", "DAVx⁵"), (r"bitwarden", "Bitwarden"), (r"immich", "Immich"), (r"paperless", "Paperless"),
        (r"infuse", "Infuse"), (r"kodi", "Kodi"), (r"plex", "Plex"), (r"emby", "Emby"), (r"syncthing", "Syncthing"),
        (r"audiobookshelf", "Audiobookshelf"), (r"navidrome|substreamer|symfonium|dsub", "Musik-App"), (r"photoprism", "PhotoPrism"),
        (r"vikunja", "Vikunja"), (r"ntfy", "ntfy"), (r"gotify", "Gotify"), (r"mealie", "Mealie"), (r"grocy", "Grocy"),
        (r"bikehelper", "BikeHelper"), (r"cfnetwork|darwin/", "iOS-App"), (r"okhttp", "Android-App"), (r"dart/", "App (Flutter)")]
_DATACENTER = re.compile(r"(?i)(amazon|aws|google cloud|google llc|microsoft|azure|digitalocean|hetzner|ovh|linode|akamai|contabo|vultr|choopa|"
                         r"alibaba|tencent|oracle|scaleway|online s\.a\.s|leaseweb|m247|datacamp|cdn77|hostinger|ionos cloud|netcup|"
                         r"psychz|colocrossing|hostroyale|serverion|pfcloud|aeza|stark industries|frantech|buyvm|g-core|gcore|cloudflare|"
                         r"hosting|datacenter|data center|server|cloud|vps|colo)")
_BROWSER = re.compile(r"(?i)mozilla/5\.0 .*(chrome|safari|firefox|edg/|opr/)")
_BAD_UA = re.compile(r"(?i)(sqlmap|nikto|nmap|masscan|nuclei|gobuster|dirbuster|wpscan|ffuf|feroxbuster|zmeu|jorgee|hello, world)")


def _match(patterns, text: str) -> str | None:
    for pat, name in patterns:
        if re.search(pat, text, re.I):
            return name
    return None


def _result(cat: str, why: list[str], name: str | None = None) -> dict:
    label, group, desc = CATEGORIES[cat]
    return {"category": cat, "label": label, "group": group, "description": desc, "who": name, "why": why}


def explain(stats: dict, public_ip: str | None) -> dict:
    """Ordnet eine Adresse einer Ursache zu. stats: ip, count, ok, auth_fail, not_found, uas (Counter), org, acme, incidents."""
    ip = stats["ip"]
    org = stats.get("org") or ""
    uas: Counter = stats.get("uas") or Counter()
    ua_text = " | ".join(u for u, _ in uas.most_common(5) if u)
    top_ua = uas.most_common(1)[0][0] if uas else ""
    count = max(1, stats.get("count") or 0)
    incidents = stats.get("incidents") or set()

    scope = ip_scope(ip)
    if scope in ("private", "loopback"):
        return _result("home", ["Private Adresse aus deinem eigenen Netz"])
    if public_ip and ip == public_ip:
        return _result("self", ["Das ist deine eigene öffentliche IP-Adresse"])
    if "bruteforce" in incidents or (stats.get("auth_fail", 0) >= 10 and stats.get("auth_fail", 0) / count > 0.6) or (stats.get("auth_fail", 0) >= 5 and stats.get("auth_fail", 0) / count > 0.9):
        return _result("bruteforce", [f"{stats.get('auth_fail', 0)} abgelehnte Anmeldungen (401/403)"] + ([f"Programm: {top_ua[:60]}"] if top_ua else []))
    research = _match(_RESEARCH, ua_text) or _match(_RESEARCH_ORG, org)
    if research:
        return _result("research", [f"Gehört zu {research}" + (f" ({org})" if org and research.lower() not in org.lower() else "")], research)
    paths = stats.get("exploit_paths") or []
    if "scanner" in incidents or _BAD_UA.search(ua_text) or len(paths) >= 2:
        why = []
        if paths:
            why.append("Hat nach Schwachstellen gesucht: " + ", ".join(sorted(set(paths))[:3]) + (" …" if len(set(paths)) > 3 else ""))
        elif "scanner" in incidents:
            why.append("Hat typische Schwachstellen abgefragt")
        if _BAD_UA.search(ua_text):
            why.append(f"Angriffswerkzeug im Programmnamen: {top_ua[:60]}")
        return _result("scan_attack", why or ["Als Angreifer erkannt"])
    if stats.get("acme"):
        return _result("acme", [f"{stats['acme']}× Abruf unter /.well-known/acme-challenge/"], "Let's Encrypt")
    monitor = _match(_MONITOR, ua_text)
    if monitor:
        return _result("monitor", [f"Programm: {monitor}"], monitor)
    crawler = _match(_CRAWLER, ua_text)
    if crawler:
        why = [f"Gibt sich als Crawler von {crawler} aus"]
        if crawler in ("Google", "Bing", "Apple") and org and not re.search(crawler if crawler != "Bing" else "microsoft", org, re.I):
            why.append(f"Achtung: Netzbetreiber ist {org}, nicht {crawler}. Vermutlich ein Bot, der sich nur so nennt")
            return _result("datacenter", why, crawler)
        return _result("crawler", why, crawler)
    preview = _match(_PREVIEW, ua_text)
    if preview:
        return _result("preview", [f"Vorschau-Abruf von {preview}"], preview)
    app = _match(_APP, ua_text)
    if app and not (stats.get("not_found", 0) / count > 0.5):
        return _result("app", [f"Programm: {app}"] + ([f"Anschluss: {org}"] if org else []), app)
    datacenter = bool(org and _DATACENTER.search(org))
    if _BROWSER.search(top_ua) and not datacenter and stats.get("ok", 0) / count >= 0.5:
        return _result("visitor", ["Normaler Browser"] + ([f"Anschluss: {org}"] if org else []))
    if stats.get("not_found", 0) / count > 0.5 and count >= 3:
        return _result("probe", [f"{stats['not_found']} von {count} Aufrufen ins Leere (404)"] + ([f"Netz: {org}"] if org else []))
    if datacenter:
        return _result("datacenter", [f"Netz: {org}"] + ([f"Programm: {top_ua[:60]}"] if top_ua else ["Kein Programmname angegeben"]))
    if _BROWSER.search(top_ua):
        return _result("visitor", ["Browser"] + ([f"Anschluss: {org}"] if org else []))
    return _result("unknown", ([f"Programm: {top_ua[:60]}"] if top_ua else ["Kein Programmname"]) + ([f"Netz: {org}"] if org else []))


def collect(db: Session, since: datetime, ips: list[str] | None = None, limit: int = 2000, extra_conds=()) -> dict[str, dict]:
    """Kennzahlen je IP für explain(). Ohne ips: die limit häufigsten Adressen im Zeitraum."""
    E = AccessEvent
    conds = [E.ts >= since, *extra_conds]
    if ips is not None:
        if not ips:
            return {}
        conds.append(E.ip.in_(ips))
    rows = db.execute(
        select(E.ip, func.count(), func.sum(case((E.status < 400, 1), else_=0)), func.sum(case((E.status.in_([401, 403]), 1), else_=0)),
               func.sum(case((E.status == 404, 1), else_=0)), func.sum(case((E.path.like("/.well-known/acme-challenge/%"), 1), else_=0)),
               func.max(E.as_org), func.max(E.country), func.count(func.distinct(E.host)), func.max(E.ts))
        .where(*conds).group_by(E.ip).order_by(func.count().desc()).limit(limit)
    ).all()
    out = {}
    for ip, n, ok, auth, nf, acme, org, country, hosts, last in rows:
        out[ip] = {"ip": ip, "count": n, "ok": ok or 0, "auth_fail": auth or 0, "not_found": nf or 0, "acme": acme or 0,
                   "org": org if org != "Heimnetz" else None, "country": country, "hosts": hosts, "last": last, "uas": Counter(), "incidents": set(),
                   "exploit_paths": [], "exploit_hits": 0}
    if not out:
        return out
    keys = list(out)
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        for ip, ua, n in db.execute(select(E.ip, E.user_agent, func.count()).where(E.ts >= since, E.ip.in_(chunk), *extra_conds)
                                    .group_by(E.ip, E.user_agent)):
            out[ip]["uas"][ua or ""] += n
        for ip, path, n in db.execute(select(E.ip, E.path, func.count()).where(E.ts >= since, E.ip.in_(chunk), E.status >= 400, *extra_conds)
                                      .group_by(E.ip, E.path)):
            if path and SCANNER_RE.search(path):
                out[ip]["exploit_paths"].append(path)
                out[ip]["exploit_hits"] += n
        for ip, kind in db.execute(select(Incident.ip, Incident.kind).where(Incident.ip.in_(chunk), Incident.last_seen >= since)):
            out[ip]["incidents"].add(kind)
    return out


def classify_ips(db: Session, since: datetime, public_ip: str | None, ips: list[str] | None = None, limit: int = 2000, extra_conds=()) -> dict[str, dict]:
    stats = collect(db, since, ips, limit, extra_conds)
    return {ip: {**explain(s, public_ip), "stats": s} for ip, s in stats.items()}


def summarize(classified: dict[str, dict]) -> list[dict]:
    """Je Kategorie: Anzahl Adressen und Zugriffe, sortiert nach Zugriffen."""
    agg: dict[str, dict] = defaultdict(lambda: {"ips": 0, "count": 0, "who": Counter()})
    for c in classified.values():
        a = agg[c["category"]]
        a["ips"] += 1
        a["count"] += c["stats"]["count"]
        if c.get("who"):
            a["who"][c["who"]] += c["stats"]["count"]
    out = []
    for cat, a in agg.items():
        label, group, desc = CATEGORIES[cat]
        out.append({"category": cat, "label": label, "group": group, "description": desc, "ips": a["ips"], "count": a["count"],
                    "who": [w for w, _ in a["who"].most_common(4)]})
    order = {"attack": 0, "friendly": 1, "service": 2, "noise": 3}
    out.sort(key=lambda x: (order[x["group"]], -x["count"]))
    return out
