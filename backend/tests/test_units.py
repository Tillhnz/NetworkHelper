from datetime import datetime

import pytest

from app import dns, sitecheck, uptime
from app.accesslog import parse_line, parse_time
from app.netutil import classify, normalize_cidr
from app.server_settings import SettingError, coerce, parse_ports

PROXY = ('[24/Oct/2026:13:55:36 +0200] - 200 200 - GET https cloud.example.de "/index.php?x=1" [Client 203.0.113.7] '
         '[Length 512] [Gzip -] [Sent-to 192.168.1.20] "Mozilla/5.0 (X11; Linux)" "-"')


def test_parse_proxy_line():
    ev = parse_line(PROXY)
    assert ev["host"] == "cloud.example.de" and ev["status"] == 200 and ev["ip"] == "203.0.113.7"
    assert ev["ts"] == datetime(2026, 10, 24, 11, 55, 36)  # in UTC umgerechnet
    assert ev["upstream"] == "192.168.1.20" and ev["referer"] is None and ev["bytes"] == 512


def test_parse_variants():
    redirect = '[24/Oct/2026:13:55:36 +0000] - - 301 - GET http nas.example.de "/" [Client 2001:db8::1] [Length 166] [Gzip -] [Sent-to nas] "curl/8" "https://a"'
    assert parse_line(redirect)["status"] == 301
    old = '[24/Oct/2026:13:55:36 +0000] 200 - GET https a.example "/x" [Client 1.2.3.4] [Length 5] [Gzip 2.5] "ua" "-"'
    assert parse_line(old)["status"] == 200
    combined = '1.2.3.4 - - [24/Oct/2026:13:55:36 +0000] "GET /wp-login.php HTTP/1.1" 404 12 "-" "zgrab/0.x"'
    ev = parse_line(combined)
    assert ev["path"] == "/wp-login.php" and ev["user_agent"] == "zgrab/0.x" and ev["host"] == "-"
    assert parse_line("kein Protokoll") is None
    assert parse_time("01/Jan/2026:00:30:00 +0100") == datetime(2025, 12, 31, 23, 30)


def test_classify_and_cidr():
    assert classify("192.168.1.5") == "private" and classify("100.70.1.1") == "private"
    assert classify("8.8.8.8") == "public" and classify("::1") == "loopback" and classify("x") == "invalid"
    assert normalize_cidr("203.0.113.9/24") == "203.0.113.0/24"
    with pytest.raises(ValueError):
        normalize_cidr("10.0.0.0/4")


def test_settings_validation():
    assert parse_ports("22, 80-82,443") == [22, 80, 81, 82, 443]
    with pytest.raises(SettingError):
        parse_ports("70000")
    assert coerce("porkbun_domains", "Example.de, beispiel.com example.de") == "example.de, beispiel.com"
    with pytest.raises(SettingError):
        coerce("porkbun_domains", "kein domain")
    assert coerce("dns_new_record_type", "CNAME") == "CNAME"
    assert coerce("public_ip_override", "") == ""


def test_dns_helpers():
    assert dns.split_fqdn("cloud.home.example.de", ["example.de", "home.example.de"]) == ("home.example.de", "cloud")
    assert dns.split_fqdn("example.de", ["example.de"]) == ("example.de", "")
    assert dns.split_fqdn("other.org", ["example.de"]) is None
    recs = [{"name": "*", "type": "A", "content": "1.2.3.4"}, {"name": "www", "type": "CNAME", "content": "example.de"},
            {"name": "*.lab", "type": "A", "content": "1.2.3.4"}, {"name": "mail", "type": "MX", "content": "x"}]
    assert dns.covered_by("www", recs)["type"] == "CNAME"
    assert dns.covered_by("pi.lab", recs)["name"] == "*.lab"
    assert dns.covered_by("cloud", recs)["name"] == "*"
    assert dns.covered_by("mail", recs[3:]) is None


def test_uptime_and_grades():
    assert uptime.status_ok(200, "200-399") and uptime.status_ok(401, "200-299,401") and not uptime.status_ok(500, "200-499")
    assert sitecheck.grade_for(100) == "A" and sitecheck.grade_for(82) == "B" and sitecheck.grade_for(10) == "F"


def test_outside_view():
    from app.portscan import outside_view
    summary = {"targets": ["84.130.20.50", "vps.example.de"], "shodan": {"ports": [80, 443]}}
    assert outside_view(summary, "84.130.20.50", 443, "scan") == "yes"
    assert outside_view(summary, "84.130.20.50", 5060, "scan") == "no"  # nur NAT-Loopback
    assert outside_view(summary, "vps.example.de", 5060, "scan") == "unknown"  # Shodan fragt nur die eigene IP
    assert outside_view({"targets": ["84.130.20.50"], "shodan": None}, "84.130.20.50", 5060, "scan") == "unknown"
    assert outside_view(None, "x", 1, "shodan") == "yes"


def test_explain_reasons():
    from collections import Counter
    from app.classify import explain

    def st(ip, ua="", n=10, **kw):
        return {"ip": ip, "count": n, "ok": kw.pop("ok", n), "uas": Counter({ua: n}), **kw}
    assert explain(st("192.168.1.5"), None)["category"] == "home"
    assert explain(st("84.1.2.3"), "84.1.2.3")["category"] == "self"
    assert explain(st("1.2.3.4", "Mozilla/5.0 (compatible; CensysInspect/1.1)"), None)["who"] == "Censys"
    assert explain(st("1.2.3.4", org="Censys, Inc."), None)["category"] == "research"
    assert explain(st("1.2.3.4", "Mozilla/5.0 (compatible; Googlebot/2.1)", org="Google LLC"), None)["category"] == "crawler"
    fake = explain(st("1.2.3.4", "Mozilla/5.0 (compatible; Googlebot/2.1)", org="Hetzner Online GmbH"), None)
    assert fake["category"] == "datacenter" and "nicht Google" in fake["why"][1]
    assert explain(st("1.2.3.4", "WhatsApp/2.23.20.0 A"), None)["category"] == "preview"
    assert explain(st("1.2.3.4", "Mozilla/5.0 (Android) Nextcloud-android/3.27"), None)["who"] == "Nextcloud"
    assert explain(st("1.2.3.4", acme=2), None)["category"] == "acme"
    assert explain(st("1.2.3.4", "Uptime-Kuma/1.23"), None)["category"] == "monitor"
    browser = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/130 Safari/537.36"
    assert explain(st("1.2.3.4", browser, org="Deutsche Telekom AG"), None)["category"] == "visitor"
    assert explain(st("1.2.3.4", browser, ok=0, not_found=10, org="DigitalOcean, LLC"), None)["category"] == "probe"
    assert explain(st("1.2.3.4", "python-requests/2.31", org="DigitalOcean, LLC"), None)["category"] == "datacenter"
    assert explain(st("1.2.3.4", "sqlmap/1.7"), None)["group"] == "attack"
    assert explain(st("1.2.3.4", incidents={"bruteforce"}), None)["category"] == "bruteforce"
    assert explain({"ip": "1.2.3.4", "count": 0}, None)["category"] == "unknown"


def test_fritzbox_own_ports_named():
    from app.portscan import DEFAULT_PORTS, SERVICES
    assert "TR-069" in SERVICES[8089] and 8089 in DEFAULT_PORTS


def test_exposure_verdicts():
    from app.exposure import PROBE_BY_PATH, _fingerprint, _mask_env, is_own_check, verdict
    env = "APP_NAME=demo\nDB_PASSWORD=supergeheim\nAPI_TOKEN=abc123\n"
    masked = _mask_env(env)
    assert "DB_PASSWORD=•••" in masked and "supergeheim" not in masked and "abc123" not in masked
    assert _mask_env("<html><body>A=1\nB=2</body></html>") is None
    page = "<!doctype html><html><title>Nextcloud</title><body>" + "x" * 500 + "</body></html>"
    base = _fingerprint(page)

    def res(status, text, ctype="text/plain"):
        return {"status": status, "text": text, "raw": text.encode(), "ctype": ctype, "location": ""}
    assert verdict(res(200, env), PROBE_BY_PATH["/.env"], base)[0] == "exposed"
    assert verdict(res(200, page, "text/html"), PROBE_BY_PATH["/.env"], base)[0] == "catchall"
    assert verdict(res(403, ""), PROBE_BY_PATH["/.env"], base)[0] == "protected"
    assert verdict(res(404, ""), PROBE_BY_PATH["/.git/config"], None)[0] == "missing"
    assert verdict(res(200, "[core]\n\trepositoryformatversion = 0\n"), PROBE_BY_PATH["/.git/config"], base)[0] == "exposed"
    assert verdict(res(200, "random bytes here", "application/octet-stream"), None, base)[0] == "unclear"
    assert verdict({"status": None, "text": "", "raw": b"", "ctype": "", "location": "", "error": "ConnectError"}, None, base)[0] == "error"
    assert is_own_check("192.168.1.10", "NetworkHelper-Exposure-Check/1.0", None)
    assert is_own_check("84.1.2.3", "NetworkHelper-Exposure-Check/1.0", "84.1.2.3")
    assert not is_own_check("45.1.2.3", "NetworkHelper-Exposure-Check/1.0", "84.1.2.3")  # Tarnung zählt nicht


def test_totp_rfc6238_and_recovery():
    from app import totp
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890"
    assert totp.code_at(secret, 59 // 30) == "287082" and totp.code_at(secret, 1111111109 // 30) == "081804"
    assert totp.verify(secret, "287082", now=59) == 1
    assert totp.verify(secret, "287 082", now=75) == 1  # ein Schritt Toleranz, Leerzeichen egal
    assert totp.verify(secret, "287082", last_step=1, now=59) is None  # nicht zweimal verwendbar
    assert totp.verify(secret, "000000", now=59) is None
    assert totp.decrypt(totp.encrypt("ABC")) == "ABC" and totp.decrypt("kaputt") is None
    codes, stored = totp.new_recovery_codes()
    assert len(codes) == 10 and totp.recovery_left(stored) == 10
    rest = totp.use_recovery(stored, codes[3].lower().replace("-", " "))
    assert totp.recovery_left(rest) == 9 and totp.use_recovery(rest, codes[3]) is None
    assert "<svg" in totp.qr_svg(totp.uri(secret, "a@b.de"))


def test_npm_default_page():
    from app.sitecheck import is_npm_default_page
    assert is_npm_default_page("<h1>Congratulations!</h1><p>You've successfully started the Nginx Proxy Manager.</p>")
    assert not is_npm_default_page("<h1>Nextcloud</h1>")


def test_app_versions_logic():
    import httpx
    from app import appversions as av
    assert av.in_range("10.9.10", ">= 10.9.0, < 10.9.11") and not av.in_range("10.9.11", "< 10.9.11")
    assert av.in_range("1.32.0", "<= 1.32.0") and not av.in_range("2.0", "< 1.5") and not av.in_range("1.0", "")
    assert av.assess("1.2.3", "v1.2.3", []) == "current" and av.assess("1.2.3", "v1.2.4", []) == "patch"
    assert av.assess("1.2.3", "1.3.0", []) == "minor" and av.assess("29.0.8", "v30.0.2", []) == "major"
    assert av.assess("1.0", "1.0", [{"id": "x"}]) == "vulnerable" and av.assess(None, "1.0", []) == "unknown"
    advs = [{"id": "GHSA-1", "summary": "XSS", "severity": "high", "url": "u", "cve": "CVE-1",
             "vulns": [{"package": "jellyfin", "range": "< 10.9.11", "patched": "10.9.11"}]}]
    assert [a["id"] for a in av.affecting(advs, "10.9.10")] == ["GHSA-1"] and av.affecting(advs, "10.10.0") == []
    req = httpx.Request("GET", "https://x")
    r = lambda j: httpx.Response(200, json=j, request=req)  # noqa: E731
    assert av._nextcloud(r({"installed": True, "versionstring": "30.0.1", "productname": "Nextcloud"})) == "30.0.1"
    assert av._jellyfin(r({"ProductName": "Jellyfin Server", "Version": "10.10.3"})) == "10.10.3"
    assert av._immich(r({"major": 1, "minor": 120, "patch": 2})) == "1.120.2"
    assert av._gitea(r({"version": "1.22.3"})) == "1.22.3" and av._gitea(r({"version": "9.0.1+gitea-1.22.0"})) is None
    assert av._forgejo(r({"version": "9.0.1+gitea-1.22.0"})) == "9.0.1"
    assert av._vaultwarden(r({"version": "2024.6.2", "server": {"name": "Vaultwarden", "version": "1.32.5"}})) == "1.32.5"
    assert av._nextcloud(r({"Version": "1"})) is None


def test_geoblock_helpers():
    from app import geoblock
    nets = geoblock.parse_feed('{"cidr":"1.10.16.0/20","sblid":"SBL1"}\n; Kommentar\n2.56.0.0/14 ; SBL2\n# x\n5.6.7.8\n{"type":"metadata"}')
    assert nets == ["1.10.16.0/20", "2.56.0.0/14", "5.6.7.8/32"]
    clean = geoblock.clean_networks(["10.0.0.0/8", "0.0.0.0/8", "1.10.16.0/20", "1.10.16.0/21", "84.130.20.0/24", "5.0.0.0/4", "fe80::/10", "2a00:1::/32"],
                                    own_ip="84.130.20.50")
    assert clean == ["1.10.16.0/20", "2a00:1::/32"]  # privat, zu groß, eigene Adresse raus; Überlappung zusammengefasst
    assert geoblock.parse_countries("de, at;CH x DE") == ["DE", "AT", "CH"]


def test_domainguard_analyze():
    from app.domainguard import analyze
    bare = analyze("example.de", [{"name": "", "type": "A", "content": "1.2.3.4"}])
    fixes = {c["key"]: c["fix"] for c in bare["checks"] if not c["ok"]}
    assert not bare["mail"] and fixes == {"null_mx": "null_mx", "spf": "spf", "dmarc": "dmarc", "caa": "caa"}
    good = analyze("example.de", [{"name": "", "type": "MX", "content": ".", "prio": "0"}, {"name": "", "type": "TXT", "content": "v=spf1 -all"},
                                  {"name": "_dmarc", "type": "TXT", "content": "v=DMARC1; p=reject"}, {"name": "", "type": "CAA", "content": '0 issue "letsencrypt.org"'}])
    assert good["ok"]
    mail = analyze("example.de", [{"name": "", "type": "MX", "content": "mx.mailbox.org", "prio": "10"}, {"name": "", "type": "CAA", "content": '0 issue "sectigo.com"'}])
    c = {x["key"]: x for x in mail["checks"]}
    assert mail["mail"] and c["dmarc"]["fix"] == "dmarc_monitor" and c["spf"]["fix"] is None and c["caa"]["severity"] == "crit"
    loose = analyze("example.de", [{"name": "", "type": "TXT", "content": '"v=spf1 include:_spf.google.com ~all"'}])
    assert next(x for x in loose["checks"] if x["key"] == "spf")["fix"] is None  # vorhandenen SPF nicht überschreiben


def test_outside_view_after_ip_change():
    from app.portscan import outside_view
    base = {"targets": ["79.208.166.153"], "started": "2026-10-25T07:00:00"}
    assert outside_view({**base, "shodan": {"ports": [], "unknown": True}}, "79.208.166.153", 443, "scan") == "unknown"
    recent = {**base, "ip_since": "2026-10-24T20:00:00", "shodan": {"ports": [80]}}
    assert outside_view(recent, "79.208.166.153", 443, "scan") == "unknown"  # Shodan war seit dem Wechsel noch nicht da
    old = {**base, "ip_since": "2026-09-01T00:00:00", "shodan": {"ports": [80]}}
    assert outside_view(old, "79.208.166.153", 443, "scan") == "no" and outside_view(old, "79.208.166.153", 80, "scan") == "yes"


def test_weak_user_agents_are_not_attacks():
    from app.detect import BAD_UA_RE, WEAK_UA_RE
    assert BAD_UA_RE.search("sqlmap/1.7") and not BAD_UA_RE.search("Go-http-client/1.1")
    assert WEAK_UA_RE.search("Go-http-client/1.1") and WEAK_UA_RE.search("Mozilla/5.0 zgrab/0.x")
    assert not BAD_UA_RE.search("Mozilla/5.0 (compatible; CensysInspect/1.1)") and not WEAK_UA_RE.search("CensysInspect/1.1")


def _agent_module():
    import importlib.util
    import os
    spec = importlib.util.spec_from_file_location("nh_agent", os.path.join(os.path.dirname(__file__), "..", "..", "agent", "nh-agent.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_agent_fail2ban_parse_and_config():
    a = _agent_module()
    out = ("Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t2\n|  |- Total failed:\t17\n"
           "|  `- Journal matches:\t_SYSTEMD_UNIT=sshd.service + _COMM=sshd\n`- Actions\n   |- Currently banned:\t2\n"
           "   |- Total banned:\t5\n   `- Banned IP list:\t45.9.9.1 2001:db8::7 bogus;rm")
    j = a.f2b_parse_jail(out)
    assert j == {"failed": 2, "total_failed": 17, "banned": 2, "total_banned": 5, "ips": ["45.9.9.1", "2001:db8::7"]}
    det = dict(sshd=True, journal=True, npm_logs="/data/logs", npm_docker=True, proxmox=True, nft=True)
    conf = a.f2b_jail_config(det, ["79.208.166.153", "x; rm -rf"])
    assert "79.208.166.153" in conf and "rm -rf" not in conf and "192.168.0.0/16" in conf
    assert "chain=DOCKER-USER" in conf and "[networkhelper-proxmox]" in conf and "backend = systemd" in conf
    assert "[networkhelper]" in conf and "bantime = -1" in conf


def test_agent_fail2ban_sync():
    a = _agent_module()
    calls = []
    a.f2b_client = lambda *args, **kw: (calls.append(args), (0, ""))[1]
    sync = a.Fail2banSync({})
    status = {"running": True, "jails": [{"name": "networkhelper", "ips": ["1.1.1.1", "2.2.2.2"]}, {"name": "sshd", "ips": ["79.208.166.153"]}]}
    sync.apply(status, ["2.2.2.2", "3.3.3.3", "10.0.0.0/8", "79.208.166.153"], ["79.208.166.153"],
               [{"jail": "sshd", "ip": "9.9.9.9"}, {"jail": "gibts; nicht", "ip": "1.2.3.4"}])
    assert ("set", "networkhelper", "banip", "3.3.3.3") in calls
    assert ("set", "networkhelper", "unbanip", "1.1.1.1") in calls
    assert ("set", "sshd", "unbanip", "9.9.9.9") in calls
    assert ("set", "sshd", "unbanip", "79.208.166.153") in calls  # eigene IP sofort frei
    assert not any("10.0.0.0/8" in c for c in calls) and not any("gibts; nicht" in c for c in calls)
    assert not any(c[:3] == ("set", "networkhelper", "banip") and c[3] == "79.208.166.153" for c in calls)


def _fake_net(monkeypatch, **over):
    from app import diagnose
    net = dict(
        resolve_public=lambda name: {"status": "ok", "a": ["79.208.166.153"], "aaaa": [], "source": "Test"},
        tcp_check=lambda host, port, timeout=4: "open",
        tls_check=lambda host, port=443, connect_to=None: {"ok": True, "days": 60, "issuer": "Let's Encrypt", "error": None},
        speaks=lambda host, port: "http",
        http_get=lambda url: {"status": 200, "server": "openresty", "text": "<html>App</html>"},
        npm_hosts=lambda: [{"id": 3, "domains": ["cloud.example.de"], "scheme": "http", "host": "192.168.1.20", "port": 80,
                            "enabled": True, "online": True, "nginx_err": None, "certificate_id": 2, "access_list": False}],
        adguard_check=lambda host: None,
    )
    net.update(over)
    for k, v in net.items():
        monkeypatch.setattr(diagnose, k, v)
    return diagnose


def _db_with_ip(ip="79.208.166.153"):
    import tempfile
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database import Base
    from app import state
    eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/d.db")
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    state.put(db, "public_ip", {"ip": ip, "since": "2026-01-01T00:00:00"})
    return db


def test_diagnose_all_fine(monkeypatch):
    d = _fake_net(monkeypatch)
    res = d.run(_db_with_ip(), "https://cloud.example.de/login")
    assert res["host"] == "cloud.example.de" and res["verdict"]["status"] == "ok"
    assert [s["key"] for s in res["steps"]] == ["dns", "ip", "port", "tls", "npm", "upstream", "http"]


def test_diagnose_finds_causes(monkeypatch):
    db = _db_with_ip()
    d = _fake_net(monkeypatch, resolve_public=lambda n: {"status": "nxdomain", "a": [], "aaaa": [], "source": "Test"},
                  http_get=lambda u: {"status": None, "error": "ConnectError"})
    v = d.run(db, "neu.example.de")["verdict"]
    assert v["status"] == "fail" and "Name im Internet" in v["title"] and "Porkbun" in v["fix"]
    d = _fake_net(monkeypatch, npm_hosts=lambda: [], http_get=lambda u: {"status": 200, "text": "Congratulations! Nginx Proxy Manager"})
    assert "kennt den Namen" in d.run(db, "cloud.example.de")["verdict"]["title"]
    d = _fake_net(monkeypatch, speaks=lambda h, p: "https", http_get=lambda u: {"status": 502, "server": "openresty", "text": "bad"})
    v = d.run(db, "cloud.example.de")["verdict"]
    assert "Dienst dahinter" in v["title"] and "https" in v["fix"]
    d = _fake_net(monkeypatch, tcp_check=lambda h, p, timeout=4: "refused" if h == "192.168.1.20" else "open",
                  http_get=lambda u: {"status": 502, "text": ""})
    assert "lehnt ab" in d.run(db, "cloud.example.de")["verdict"]["text"]
    d = _fake_net(monkeypatch, resolve_public=lambda n: {"status": "ok", "a": ["84.1.1.1"], "aaaa": [], "source": "T"})
    from app import notify
    notify.raise_alert(db, "info", "ip", "Neue öffentliche IP: 79.208.166.153", "Vorher: 84.1.1.1")
    v = d.run(db, "cloud.example.de")["verdict"]
    assert v["status"] == "fail" and "frühere IP" in v["text"] and "DynDNS" in v["fix"]
    d = _fake_net(monkeypatch, npm_hosts=lambda: [{"id": 3, "domains": ["*.example.de"], "scheme": "http", "host": "x", "port": 80,
                                                   "enabled": True, "online": False, "nginx_err": "cannot load certificate", "certificate_id": 2,
                                                   "access_list": False}], http_get=lambda u: {"status": 200, "text": "Congratulations! Nginx Proxy Manager"})
    v = d.run(db, "cloud.example.de")["verdict"]
    assert "Offline" in v["text"] and "cannot load certificate" in v["text"]
    d = _fake_net(monkeypatch, tcp_check=lambda h, p, timeout=4: "refused" if (h, p) == ("79.208.166.153", 80) else "open")
    v = d.run(db, "cloud.example.de")["verdict"]
    assert v["status"] == "warn" and "Port 80" in v["title"]


def test_cert_errors_explained():
    from app import certs
    why, fix = certs.explain("Some challenges have failed. Timeout during connect (likely firewall problem)")
    assert "Port 80" in why and "FRITZ!Box" in fix
    assert "DNS" in certs.explain("DNS problem: NXDOMAIN looking up A for x.example.de")[0]
    assert "zu viele" in certs.explain("Error creating new order :: too many certificates already issued")[0]
    assert "läuft gerade" in certs.explain("Another instance of Certbot is already running.")[0]
    assert certs.explain("etwas ganz anderes")[0].startswith("Der Proxy Manager meldet")


def test_cert_auto_renew(monkeypatch):
    from datetime import timedelta
    from app import certs, npm
    from app.config import settings
    from app.models import Alert
    db = _db_with_ip()
    soon = (datetime.utcnow() + timedelta(days=5)).strftime("%Y-%m-%d %H:%M:%S")
    later = (datetime.utcnow() + timedelta(days=60)).strftime("%Y-%m-%d %H:%M:%S")
    monkeypatch.setattr(settings, "cert_auto_renew", True)
    monkeypatch.setattr(settings, "cert_auto_renew_days", 14)
    monkeypatch.setattr(npm, "configured", lambda: True)
    monkeypatch.setattr(npm, "certificates", lambda: [
        {"id": 1, "name": "bald.example.de", "provider": "letsencrypt", "expires_on": soon},
        {"id": 2, "name": "spaeter.example.de", "provider": "letsencrypt", "expires_on": later},
        {"id": 3, "name": "eigenes", "provider": "other", "expires_on": soon}])
    calls = []

    def fail(cid):
        calls.append(cid)
        raise npm.NpmError("Timeout during connect (likely firewall problem)")
    monkeypatch.setattr(npm, "renew_certificate", fail)
    certs.run(db)
    assert calls == [1]
    alert = db.query(Alert).filter(Alert.kind == "cert").one()
    assert alert.severity == "crit" and "Port 80" in alert.body
    certs.run(db)  # Pause nach Fehlversuch
    assert calls == [1]
    monkeypatch.setattr(npm, "raw_proxy_hosts", lambda: [{"certificate_id": 1, "domains": ["bald.example.de"]}])
    ov = certs.overview(db)
    assert ov["items"][0]["id"] == 1 and ov["items"][0]["last"]["ok"] is False and ov["items"][0]["used_by"] == ["bald.example.de"]
    assert not next(i for i in ov["items"] if i["id"] == 3)["renewable"]


def test_diagnose_adguard(monkeypatch):
    db = _db_with_ip()
    d = _fake_net(monkeypatch, adguard_check=lambda h: {"blocked": True, "reason_label": "Filterliste", "rule": "||example.de^", "rewrite": None, "npm_ip": "192.168.1.5"})
    v = d.run(db, "cloud.example.de")["verdict"]
    assert v["status"] == "fail" and "AdGuard" in v["title"] and "freigeben" in v["fix"]
    d = _fake_net(monkeypatch, adguard_check=lambda h: {"blocked": False, "rewrite": "192.168.1.99", "npm_ip": "192.168.1.5", "reason_label": ""})
    assert d.run(db, "cloud.example.de")["verdict"]["status"] == "warn"


def test_adguard_parsing_and_alerts(monkeypatch):
    from app import adguard, npm
    from app.config import settings
    from app.models import Alert
    monkeypatch.setattr(settings, "adguard_url", "http://192.168.1.53")
    monkeypatch.setattr(settings, "npm_url", "http://192.168.1.5:81")
    log = {"data": []}

    def fake(method, path, json=None, params=None, timeout=10):
        if path == "/status":
            return {"version": "v0.107.52", "running": True, "protection_enabled": True}
        if path == "/querylog":
            return log
        if path == "/stats":
            return {"num_dns_queries": 1000, "num_blocked_filtering": 150, "num_replaced_safebrowsing": 2,
                    "top_blocked_domains": [{"ads.example.com": 90}], "top_clients": [{"192.168.1.20": 500}]}
        raise AssertionError(path)
    monkeypatch.setattr(adguard, "_req", fake)
    st = adguard.stats()
    assert st["blocked_pct"] == 15.2 and st["top_blocked"] == [{"name": "ads.example.com", "count": 90}]
    db = _db_with_ip()
    adguard.run(db)  # erster Lauf merkt sich nur den Stand
    log["data"] = [{"time": "2026-10-29T10:00:00.1+01:00", "question": {"name": "evil.example", "type": "A"},
                    "client": "192.168.1.20", "client_info": {"name": "Laptop"}, "reason": "FilteredSafeBrowsing"}]
    adguard.run(db)
    alert = db.query(Alert).filter(Alert.kind == "adguard").one()
    assert "Laptop" in alert.title and "evil.example" in alert.body
    adguard.run(db)
    assert db.query(Alert).filter(Alert.kind == "adguard").count() == 1
    monkeypatch.setattr(npm, "configured", lambda: True)
    monkeypatch.setattr(npm, "raw_proxy_hosts", lambda: [{"enabled": True, "domains": ["a.example.de", "b.example.de", "c.other.de"]}])
    sug = adguard.suggestions([{"domain": "c.other.de", "answer": "192.168.1.7"}])
    assert sug["ip"] == "192.168.1.5" and sug["items"] == ["a.example.de", "b.example.de"]
    assert sug["wildcards"] == ["*.example.de"] and sug["wrong"][0]["domain"] == "c.other.de"


def _fake_pve(monkeypatch, users=None, guests_status="running"):
    import time
    from app import proxmox
    from app.config import settings
    monkeypatch.setattr(settings, "proxmox_url", "https://192.168.1.2:8006")
    monkeypatch.setattr(settings, "proxmox_token_id", "networkhelper@pve!monitor")
    monkeypatch.setattr(settings, "proxmox_token_secret", "x")
    monkeypatch.setattr(proxmox, "_check_fp", lambda: None)
    now = int(time.time())
    routes = {
        "/version": {"version": "8.4.1"},
        "/nodes": [{"node": "pve", "status": "online", "uptime": 1000}],
        "/cluster/resources?type=vm": [
            {"vmid": 101, "name": "npm", "type": "lxc", "node": "pve", "status": "running"},
            {"vmid": 102, "name": "docker", "type": "lxc", "node": "pve", "status": guests_status},
            {"vmid": 200, "name": "ha", "type": "qemu", "node": "pve", "status": "running"}],
        "/access/users?full=1": users or [{"userid": "root@pam", "enable": 1}],
        "/access/tfa": [],
        "/cluster/firewall/options": {"enable": 0},
        "/cluster/backup": [{"id": "daily"}],
        "/nodes/pve/apt/update": [{"Package": "openssl", "Origin": "Debian-Security", "Section": "utils"}],
        "/nodes/pve/status": {"pveversion": "pve-manager/8.4.1/abc"},
        "/nodes/pve/storage?content=backup&enabled=1": [{"storage": "backup"}],
        "/nodes/pve/storage/backup/content?content=backup": [{"vmid": 101, "ctime": now - 3600}, {"vmid": 200, "ctime": now - 20 * 86400}],
        "/nodes/pve/lxc/101/config": {"unprivileged": 1, "onboot": 1},
        "/nodes/pve/lxc/102/config": {"features": "nesting=1", "onboot": 1, "mp0": "/mnt/data,mp=/data"},
        "/nodes/pve/qemu/200/config": {"agent": "1"},
    }
    monkeypatch.setattr(proxmox, "_get", lambda c, path: routes.get(path))
    return proxmox


def test_proxmox_checks_and_alerts(monkeypatch):
    from app.models import Alert
    pve = _fake_pve(monkeypatch)
    snap = pve.collect()
    g = {x["vmid"]: x for x in snap["guests"]}
    assert g[101]["checks"] == []
    assert g[102]["checks"][0]["level"] == "crit" and "Nesting" in g[102]["checks"][0]["text"]
    assert any("Keine Sicherung" in c["text"] for c in g[102]["checks"])
    assert any("vor 20 Tagen" in c["text"] for c in g[200]["checks"])
    texts = " ".join(c["text"] for c in snap["host_checks"])
    assert "root@pam" in texts and "openssl" in texts
    db = _db_with_ip()
    pve.run(db)
    assert db.query(Alert).filter(Alert.kind == "proxmox", Alert.severity == "crit").count() == 1  # privilegiert + Nesting
    pve = _fake_pve(monkeypatch, users=[{"userid": "root@pam", "enable": 1}, {"userid": "hacker@pve", "enable": 1}], guests_status="stopped")
    pve.run(db)
    titles = [a.title for a in db.query(Alert).filter(Alert.kind == "proxmox")]
    assert "Neues Proxmox-Konto: hacker@pve" in titles and any("docker" in t and "läuft nicht" in t for t in titles)
