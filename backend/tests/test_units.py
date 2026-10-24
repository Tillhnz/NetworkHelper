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
