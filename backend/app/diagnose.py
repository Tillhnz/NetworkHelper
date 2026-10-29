"""Fehlersuche: Warum ist ein Dienst nicht erreichbar?

Prüft die Kette, die ein Besucher durchläuft, Schritt für Schritt und nennt die erste Stelle, an der es hakt:
1. Gibt es den Namen im Internet (DNS, über einen öffentlichen Resolver, unabhängig von AdGuard & Co.)?
2. Zeigt er auf deinen Anschluss (aktuelle öffentliche IP, DynDNS)?
3. Nimmt dein Router die Verbindung an (Portfreigabe 443, für Let's Encrypt auch 80)?
4. Passt das Zertifikat?
5. Kennt der Proxy Manager den Namen, ist der Proxy Host aktiv und fehlerfrei geladen?
6. Erreicht man das Ziel dahinter (IP/Port, http oder https)?
7. Was antwortet die Seite?

Netzwerkzugriffe stecken in kleinen Funktionen, damit Tests sie ersetzen können.
"""
from __future__ import annotations

import json
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from . import npm, publicip
from .config import settings
from .sitecheck import is_npm_default_page

DOH_URL = "https://cloudflare-dns.com/dns-query"
STEP_TIMEOUT = 5


# ---------- Netzwerk (in Tests ersetzbar) ----------

def resolve_public(name: str) -> dict:
    """A/AAAA über DNS-over-HTTPS. {'status': 'ok'|'nxdomain'|'error', 'a': [...], 'aaaa': [...], 'source': ...}"""
    out = {"status": "error", "a": [], "aaaa": [], "source": "Cloudflare (öffentlich)"}
    try:
        for rtype, key in (("A", "a"), ("AAAA", "aaaa")):
            r = httpx.get(DOH_URL, params={"name": name, "type": rtype}, headers={"Accept": "application/dns-json"}, timeout=STEP_TIMEOUT)
            d = r.json()
            if d.get("Status") == 3:
                return {**out, "status": "nxdomain"}
            want = 1 if rtype == "A" else 28
            out[key] = [a["data"] for a in d.get("Answer", []) if a.get("type") == want]
        out["status"] = "ok"
        return out
    except (httpx.HTTPError, ValueError):
        pass
    try:  # Rückfall: Resolver des Servers (kann von AdGuard/Pi-hole umgeschrieben sein)
        infos = socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)
        out["a"] = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
        out["aaaa"] = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
        return {**out, "status": "ok", "source": "Resolver dieses Servers"}
    except socket.gaierror:
        return {**out, "status": "nxdomain", "source": "Resolver dieses Servers"}


def tcp_check(host: str, port: int, timeout: float = 4) -> str:
    """'open', 'refused', 'timeout' oder 'unresolvable'."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "refused"
    except socket.gaierror:
        return "unresolvable"
    except (TimeoutError, socket.timeout):
        return "timeout"
    except OSError:
        return "refused"


def tls_check(host: str, port: int = 443, connect_to: str | None = None) -> dict:
    """Zertifikat prüfen (mit SNI). {'ok', 'error', 'expires', 'issuer', 'days'}"""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((connect_to or host, port), timeout=STEP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        days = (exp - datetime.now(timezone.utc).replace(tzinfo=None)).days
        return {"ok": True, "expires": exp.isoformat(), "issuer": issuer.get("organizationName"), "days": days, "error": None}
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "error": e.verify_message or str(e)}
    except (OSError, ssl.SSLError) as e:
        return {"ok": False, "error": f"Keine TLS-Verbindung ({e.__class__.__name__})", "no_tls": True}


def speaks(host: str, port: int) -> str:
    """Welche Sprache spricht ein Dienst? 'http', 'https' oder 'unknown'."""
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            s.settimeout(3)
            s.sendall(b"GET / HTTP/1.0\r\nHost: networkhelper\r\n\r\n")
            data = s.recv(400)
    except OSError:
        return "unknown"
    if data.startswith(b"HTTP/"):
        return "https" if b"plain HTTP request was sent to HTTPS" in data or b"speaking plain HTTP to an SSL" in data else "http"
    if data[:1] == b"\x15" or data[:2] == b"\x16\x03":  # TLS-Alarm oder Handshake: der Dienst erwartet https
        return "https"
    # Keine Antwort auf Klartext: gelingt ein TLS-Handshake, spricht der Dienst https
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            with ctx.wrap_socket(s):
                return "https"
    except (OSError, ssl.SSLError):
        return "unknown"


def http_get(url: str) -> dict:
    try:
        r = httpx.get(url, timeout=10, verify=False, follow_redirects=False, headers={"User-Agent": "NetworkHelper-Diagnose/1.0"})
        return {"status": r.status_code, "server": r.headers.get("server", ""), "location": r.headers.get("location", ""),
                "text": r.text[:20000]}
    except httpx.RemoteProtocolError:
        return {"status": None, "error": "closed"}
    except httpx.HTTPError as e:
        return {"status": None, "error": e.__class__.__name__}


def npm_hosts() -> list[dict] | None:
    if not npm.configured():
        return None
    return npm.raw_proxy_hosts()


def adguard_check(host: str) -> dict | None:
    from . import adguard
    if not adguard.configured():
        return None
    try:
        return {**adguard.check_host(host), "npm_ip": adguard.npm_lan_ip()}
    except adguard.AdGuardError as e:
        return {"error": str(e)}


# ---------- Auswertung ----------

def _step(steps, key, label, status, detail, fix=None):
    steps.append({"key": key, "label": label, "status": status, "detail": detail, "fix": fix})


def host_of(value: str) -> str:
    value = value.strip()
    if "://" in value:
        return (urlparse(value).hostname or "").lower()
    return value.split("/")[0].split(":")[0].lower()


def run(db: Session, target: str) -> dict:
    host = host_of(target)
    steps: list[dict] = []
    if not host or "." not in host:
        raise ValueError("Bitte einen Hostnamen wie cloud.example.de angeben")
    pub = publicip.info(db).get("ip")
    own = {p[0] for p in publicip.own_periods(db)}
    fritz = settings.router_type == "fritzbox"

    # 1. DNS
    dns = resolve_public(host)
    if dns["status"] == "nxdomain":
        _step(steps, "dns", "Name im Internet bekannt", "fail", f"„{host}“ gibt es im DNS nicht ({dns['source']}).",
              "Bei Porkbun einen Eintrag anlegen: DNS → Abgleich mit dem Proxy Manager → „Anlegen“, oder einen Platzhalter *.domain.")
    elif dns["status"] == "error" or not (dns["a"] or dns["aaaa"]):
        _step(steps, "dns", "Name im Internet bekannt", "warn", "DNS ließ sich nicht abfragen oder lieferte keine Adresse.")
    else:
        _step(steps, "dns", "Name im Internet bekannt", "ok", f"{', '.join(dns['a'] + dns['aaaa'])} ({dns['source']})")

    # 2. Zeigt auf deinen Anschluss?
    if dns["a"] and pub:
        if pub in dns["a"]:
            _step(steps, "ip", "Zeigt auf deinen Anschluss", "ok", f"{pub} ist deine aktuelle öffentliche IP.")
        elif own & set(dns["a"]):
            _step(steps, "ip", "Zeigt auf deinen Anschluss", "fail", f"Der Name zeigt noch auf deine frühere IP {', '.join(dns['a'])}, aktuell ist {pub}.",
                  "DynDNS hat die neue Adresse noch nicht eingetragen: DNS → DynDNS „Jetzt aktualisieren“. Danach kann es einige Minuten dauern (TTL).")
        else:
            _step(steps, "ip", "Zeigt auf deinen Anschluss", "warn", f"Der Name zeigt auf {', '.join(dns['a'])}, deine IP ist {pub}.",
                  "Gewollt (z. B. ein Server im Rechenzentrum)? Sonst den A-Eintrag bei Porkbun auf deine IP setzen oder DynDNS dafür einschalten.")
        if dns["aaaa"]:
            _step(steps, "ipv6", "IPv6-Eintrag (AAAA)", "info", f"Auch IPv6: {', '.join(dns['aaaa'])}. Geräte mit IPv6 nehmen diesen zuerst.",
                  "Klappt es nur bei manchen Geräten nicht (oft Handys im Mobilfunk), den AAAA-Eintrag prüfen oder löschen.")
    elif not pub:
        _step(steps, "ip", "Zeigt auf deinen Anschluss", "skip", "Deine öffentliche IP ist noch nicht bekannt.")

    # 3. Router / Portfreigabe
    target_ip = pub if pub and (not dns["a"] or pub in dns["a"] or own & set(dns["a"])) else (dns["a"][0] if dns["a"] else None)
    if target_ip:
        p443 = tcp_check(target_ip, 443)
        if p443 == "open":
            _step(steps, "port", "Router nimmt Verbindungen an (443)", "ok", f"{target_ip}:443 antwortet.")
        else:
            why = "abgelehnt" if p443 == "refused" else "keine Antwort"
            _step(steps, "port", "Router nimmt Verbindungen an (443)", "fail", f"{target_ip}:443: {why}." + (
                "" if fritz else " Hinweis: Manche Router lassen Tests aus dem eigenen Netz über die öffentliche IP nicht zu."),
                  "In der FRITZ!Box unter Internet → Freigaben → Portfreigaben prüfen: Port 443 (und 80) zum Container mit dem Proxy Manager. "
                  "Läuft der Proxy-Manager-Container?" if fritz else "Portfreigabe 443 (und 80) zum Proxy Manager im Router prüfen.")
        if p443 == "open" and tcp_check(target_ip, 80) != "open":
            _step(steps, "port80", "Port 80 für Let's Encrypt", "warn", f"{target_ip}:80 antwortet nicht.",
                  "Let's Encrypt prüft beim Erneuern über Port 80. Ohne Freigabe für 80 laufen Zertifikate nach 90 Tagen ab.")

    # 4. Zertifikat
    tls = tls_check(host, connect_to=target_ip) if target_ip else tls_check(host)
    if tls.get("ok"):
        status = "warn" if tls["days"] < 14 else "ok"
        _step(steps, "tls", "Zertifikat passt", status, f"{tls.get('issuer') or '?'}, noch {tls['days']} Tage gültig.",
              "Zertifikat erneuern: Sicherheit → Zertifikate & Header → Zertifikate im Proxy Manager." if status == "warn" else None)
    elif tls.get("no_tls"):
        _step(steps, "tls", "Zertifikat passt", "skip", tls["error"])
    else:
        err = tls.get("error") or ""
        hint = ("Das Zertifikat ist abgelaufen." if "expired" in err else
                "Das Zertifikat gehört zu einem anderen Namen." if "match" in err or "mismatch" in err else
                "Das Zertifikat ist nicht vertrauenswürdig (selbst signiert oder Standardzertifikat des Proxy Managers)." if "self" in err or "local issuer" in err else err)
        _step(steps, "tls", "Zertifikat passt", "fail", hint,
              "Im Proxy Manager beim Proxy Host unter „SSL“ ein gültiges Zertifikat für genau diesen Namen wählen oder anfordern.")

    # 5. Proxy Manager
    hosts = None
    try:
        hosts = npm_hosts()
    except npm.NpmError as e:
        _step(steps, "npm", "Proxy Manager kennt den Namen", "skip", f"Proxy Manager nicht abfragbar: {e}")
    ph = npm.find_host(hosts, host) if hosts is not None else None
    if hosts is not None:
        if ph is None:
            _step(steps, "npm", "Proxy Manager kennt den Namen", "fail", f"Kein Proxy Host für „{host}“.",
                  "Im Proxy Manager unter Hosts → Proxy Hosts einen Eintrag mit genau diesem Namen anlegen (Schreibweise prüfen).")
        elif not ph["enabled"]:
            _step(steps, "npm", "Proxy Manager kennt den Namen", "fail", "Der Proxy Host ist deaktiviert.",
                  "Im Proxy Manager beim Host über das Drei-Punkte-Menü „Enable“ wählen.")
        elif not ph["online"]:
            _step(steps, "npm", "Proxy Manager kennt den Namen", "fail", "Der Proxy Host ist „Offline“: nginx konnte ihn nicht laden. "
                  + (f"Fehler: {str(ph['nginx_err'])[:300]}" if ph.get("nginx_err") else ""),
                  "Host im Proxy Manager öffnen und speichern; meist fehlt das Zertifikat oder eine eigene Konfiguration (Advanced) ist fehlerhaft.")
        else:
            _step(steps, "npm", "Proxy Manager kennt den Namen", "ok",
                  f"Proxy Host #{ph['id']} leitet weiter an {ph['scheme']}://{ph['host']}:{ph['port']}"
                  + ("" if ph["certificate_id"] else ", ohne Zertifikat") + (", mit Zugriffsliste" if ph["access_list"] else ""))

    # 6. Ziel hinter dem Proxy Manager
    if ph and ph["enabled"]:
        state = tcp_check(str(ph["host"]), int(ph["port"] or 80), timeout=3)
        target = f"{ph['host']}:{ph['port']}"
        if state == "unresolvable":
            _step(steps, "upstream", "Dienst dahinter erreichbar", "skip",
                  f"„{ph['host']}“ ist nur im Netz des Proxy Managers bekannt (z. B. ein Docker-Name), von hier nicht prüfbar.")
        elif state == "refused":
            _step(steps, "upstream", "Dienst dahinter erreichbar", "fail", f"{target} lehnt ab: Dort läuft nichts auf diesem Port.",
                  "Läuft der Dienst bzw. sein Container? Stimmt der Port im Proxy Host (z. B. Nextcloud 80/443, Jellyfin 8096, Proxmox 8006)?")
        elif state == "timeout":
            _step(steps, "upstream", "Dienst dahinter erreichbar", "fail", f"{target} antwortet nicht.",
                  "Ist der Container/die VM an? Stimmt die IP (hat sie sich per DHCP geändert)? Eine feste IP in der FRITZ!Box vergeben hilft.")
        else:
            lang = speaks(str(ph["host"]), int(ph["port"] or 80))
            if lang != "unknown" and lang != ph["scheme"]:
                _step(steps, "upstream", "Dienst dahinter erreichbar", "fail",
                      f"{target} spricht {lang}, im Proxy Host steht aber „{ph['scheme']}“.",
                      f"Im Proxy Manager beim Host „Scheme“ auf {lang} stellen. Typisch: Proxmox (8006) und UniFi (8443) sprechen https.")
            else:
                _step(steps, "upstream", "Dienst dahinter erreichbar", "ok", f"{target} antwortet ({lang if lang != 'unknown' else 'Sprache nicht erkannt'}).")

    # 7. Antwort der Seite
    res = http_get(f"https://{host}/")
    st = res.get("status")
    if st is None:
        if res.get("error") == "closed":
            _step(steps, "http", "Seite antwortet", "fail", "Die Verbindung wurde ohne Antwort geschlossen.",
                  "Typisch für eine Sperre (Sperrliste, Ländersperre oder fail2ban) oder einen abstürzenden Dienst. Unter Sicherheit → Sperrliste nachsehen.")
        else:
            _step(steps, "http", "Seite antwortet", "fail", f"Keine Antwort ({res.get('error')}).")
    elif is_npm_default_page(res.get("text", "")):
        _step(steps, "http", "Seite antwortet", "fail", "Es kommt nur die Standardseite „Congratulations!“ des Proxy Managers.",
              "Der Proxy Manager kennt den Namen nicht oder der Host ist offline (siehe oben).")
    elif st in (502, 504):
        _step(steps, "http", "Seite antwortet", "fail", f"{st}: Der Proxy Manager erreicht den Dienst dahinter nicht.",
              "Ziel-IP, Port und http/https im Proxy Host prüfen; läuft der Dienst?")
    elif st >= 500:
        _step(steps, "http", "Seite antwortet", "fail", f"{st}: Der Dienst meldet einen eigenen Fehler.",
              "Ins Protokoll des Dienstes schauen (Container-Log). Der Weg dorthin funktioniert.")
    elif st in (401, 403):
        _step(steps, "http", "Seite antwortet", "info", f"{st}: Anmeldung nötig oder Zugriff verweigert (Zugriffsliste, Sperre oder die App selbst).")
    elif 300 <= st < 400:
        _step(steps, "http", "Seite antwortet", "ok", f"{st}: leitet weiter nach {res.get('location') or '?'}")
    else:
        _step(steps, "http", "Seite antwortet", "ok" if st < 400 else "warn", f"{st} vom Server „{res.get('server') or '?'}“.")

    # 8. Heimnetz: AdGuard Home
    ag = adguard_check(host)
    label = "Im Heimnetz (AdGuard Home)"
    if ag is None:
        pass
    elif ag.get("error"):
        _step(steps, "adguard", label, "warn", f"AdGuard Home nicht abfragbar: {ag['error']}",
              "Fällt AdGuard aus, können Geräte im Heimnetz gar keine Seiten mehr aufrufen. Container/VM von AdGuard prüfen.")
    elif ag.get("blocked"):
        _step(steps, "adguard", label, "fail", f"AdGuard sperrt den Namen im Heimnetz ({ag['reason_label']}"
              + (f", Regel {ag['rule']}" if ag.get("rule") else "") + "). Von außen geht es, zu Hause nicht.",
              "Unter DNS → AdGuard Home den Namen freigeben.")
    elif ag.get("rewrite"):
        good = ag["rewrite"] in (ag.get("npm_ip"), pub)
        _step(steps, "adguard", label, "ok" if good else "warn",
              f"Zu Hause zeigt der Name per Umschreibung auf {ag['rewrite']}."
              + ("" if good else (f" Der Proxy Manager hat aber {ag['npm_ip']}." if ag.get("npm_ip") else "")),
              None if good else "Unter DNS → AdGuard Home die Umschreibung auf die Adresse des Proxy Managers ändern.")
    else:
        _step(steps, "adguard", label, "info" if ag.get("npm_ip") else "ok",
              "Nicht gesperrt. Zu Hause geht die Anfrage über deine öffentliche IP und den Router."
              + (f" Schneller und robuster: eine Umschreibung auf {ag['npm_ip']}." if ag.get("npm_ip") else ""))

    return {"host": host, "checked_at": datetime.utcnow().isoformat(), "steps": steps, "verdict": verdict(steps)}


def verdict(steps: list[dict]) -> dict:
    fail = next((s for s in steps if s["status"] == "fail"), None)
    http_ok = any(s["key"] == "http" and s["status"] in ("ok", "info") for s in steps)
    if fail and not (http_ok and fail["key"] in ("port", "port80")):
        return {"status": "fail", "title": f"Problem bei: {fail['label']}", "text": fail["detail"], "fix": fail.get("fix")}
    warn = next((s for s in steps if s["status"] == "warn"), None)
    if warn:
        return {"status": "warn", "title": "Erreichbar, aber: " + warn["label"], "text": warn["detail"], "fix": warn.get("fix")}
    return {"status": "ok", "title": "Alles in Ordnung", "text": "Jede Station von DNS bis zur Seite funktioniert.", "fix": None}


def summary_text(res: dict) -> str:
    v = res["verdict"]
    lines = [f"Vermutliche Ursache: {v['title']}", v["text"]]
    if v.get("fix"):
        lines.append(f"So behebst du es: {v['fix']}")
    return "\n".join(lines)


def dumps(res: dict) -> str:
    return json.dumps(res)[:20000]
