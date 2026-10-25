from datetime import datetime, timedelta

from app import detect, notify, porkbun, uptime
from app.config import settings
from app.database import SessionLocal
from app.models import Alert, Incident, Monitor


def line(ip, status=200, path="/", host="cloud.example.de", ua="Mozilla/5.0", ts=None):
    ts = (ts or datetime.utcnow()).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'[{ts}] - {status} {status} - GET https {host} "{path}" [Client {ip}] [Length 100] [Gzip -] [Sent-to 192.168.1.20] "{ua}" "-"'


def test_auth_flow(client, admin):
    assert client.get("/api/me").status_code == 401
    me = client.get("/api/me", headers=admin).json()
    assert me["is_admin"] and me["alert_email"] is True
    r = client.post("/api/auth/register", json={"email": "user@example.de", "password": "geheim1234"})
    user = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.get("/api/me", headers=user).json()["is_admin"] is False
    assert client.get("/api/admin/settings", headers=user).status_code == 403
    assert client.post("/api/auth/login", json={"email": "admin@example.de", "password": "falsch"}).status_code == 401


def test_agent_ingest_and_summary(client, admin):
    r = client.post("/api/agents", headers=admin, json={"name": "Proxy-LXC"})
    assert r.status_code == 201
    token = r.json()["token"]
    assert "install.sh" in r.json()["command"] and token.startswith("nh_")
    ah = {"Authorization": f"Bearer {token}"}
    assert client.post("/api/agent/logs", json={"lines": []}, headers={"Authorization": "Bearer falsch"}).status_code == 401

    lines = [line("185.220.101.7") for _ in range(5)] + [line("192.168.1.50", path="/api")] + [line("89.248.165.4", 404, "/x")] + ["Müll"]
    r = client.post("/api/agent/logs", json={"lines": lines}, headers=ah)
    assert r.json() == {"stored": 7, "unreadable": 1}

    r = client.post("/api/agent/state", headers=ah, json={
        "hostname": "npm", "version": "1.0.0", "info": {"addrs": ["192.168.1.10"]},
        "established": [{"proto": "tcp", "local": "192.168.1.10", "lport": 443, "remote": "185.220.101.7", "rport": 51515, "process": "nginx"},
                        {"proto": "tcp", "local": "192.168.1.10", "lport": 22, "remote": "192.168.1.2", "rport": 50000, "process": "sshd"}],
        "listening": [{"proto": "tcp", "addr": "0.0.0.0", "port": 443, "process": "nginx"}],
        "enforce_blocks": True, "block_status": "ok"})
    assert r.status_code == 200 and r.json()["blocklist"] == []

    conns = client.get("/api/connections", headers=admin).json()
    assert conns[0]["online"] and conns[0]["established"][0]["scope"] == "public"

    s = client.get("/api/access/summary?range=24h", headers=admin).json()
    assert s["total"] == 7 and s["unique_ips"] == 3 and s["errors"] == 1
    assert s["hosts"][0] == {"host": "cloud.example.de", "count": 7}
    assert sum(b["2"] for b in s["series"]) == 6
    ext = client.get("/api/access/summary?range=24h&scope=external", headers=admin).json()
    assert ext["total"] == 6
    ev = client.get("/api/access/events?range=1h&status=4", headers=admin).json()
    assert len(ev["items"]) == 1 and ev["items"][0]["ip"] == "89.248.165.4"
    detail = client.get("/api/access/ip/185.220.101.7", headers=admin).json()
    assert detail["total"] == 5 and detail["hosts"][0]["host"] == "cloud.example.de"


def test_detection_and_blocking(client, admin):
    token = client.post("/api/agents", headers=admin, json={"name": "zweiter"}).json()["token"]
    ah = {"Authorization": f"Bearer {token}"}
    attack = [line("45.155.205.99", 401, "/login", host="vault.example.de") for _ in range(25)]
    attack += [line("45.155.205.99", 404, "/.env"), line("45.155.205.99", 404, "/wp-login.php", ua="sqlmap/1.7")]
    client.post("/api/agent/logs", json={"lines": attack}, headers=ah)
    settings.auto_block = True
    with SessionLocal() as db:
        changed = detect.run(db)
        kinds = {i.kind for i in changed}
        assert {"bruteforce", "scanner", "badagent"} <= kinds
        assert detect.is_blocked(db, "45.155.205.99") is not None
        assert db.query(Alert).filter(Alert.kind == "incident").count() >= 2
        # Zweiter Lauf ohne neue Zeilen erzeugt nichts Neues
        assert detect.run(db) == []
    settings.auto_block = False

    inc = client.get("/api/security/incidents", headers=admin).json()
    brute = next(i for i in inc if i["kind"] == "bruteforce")
    assert brute["severity"] == "crit" and brute["blocked"] and brute["count"] == 25
    assert client.put(f"/api/security/incidents/{brute['id']}/ack", headers=admin).json()["acknowledged"]

    blocks = client.get("/api/security/blocks", headers=admin).json()
    assert blocks["items"][0]["cidr"] == "45.155.205.99" and blocks["items"][0]["auto"]
    r = client.post("/api/agent/state", headers=ah, json={"enforce_blocks": True})
    assert "45.155.205.99" in r.json()["blocklist"]

    # Abgewiesene Zugriffe werden markiert und nicht erneut als Angriff gezählt
    client.post("/api/agent/logs", json={"lines": [line("45.155.205.99", 403, "/login")]}, headers=ah)
    assert client.get("/api/access/summary?range=1h&status=blocked", headers=admin).json()["total"] == 1

    assert client.post("/api/security/blocks", headers=admin, json={"cidr": "192.168.1.10"}).status_code == 422
    r = client.post("/api/security/blocks", headers=admin, json={"cidr": "198.51.100.0/24", "reason": "test", "hours": 2})
    assert r.status_code == 201 and r.json()["expires_at"]
    assert client.delete(f"/api/security/blocks/{r.json()['id']}", headers=admin).status_code == 204


def test_monitors(client, admin, monkeypatch):
    results = iter([{"ok": False, "latency_ms": None, "status": None, "error": "Keine Verbindung"}] * 2
                   + [{"ok": True, "latency_ms": 42, "status": 200, "error": None}])
    monkeypatch.setattr(uptime, "probe", lambda *a: next(results))
    monkeypatch.setattr("app.routers.monitors._check_soon", lambda ids: None)
    r = client.post("/api/monitors", headers=admin, json={"name": "Nextcloud", "url": "https://cloud.example.de/status.php"})
    assert r.status_code == 201
    mid = r.json()["id"]
    with SessionLocal() as db:
        uptime.run_due(db, force_ids=[mid])
        assert db.get(Monitor, mid).state == "unknown"  # ein Fehlschlag reicht nicht
        uptime.run_due(db, force_ids=[mid])
        assert db.get(Monitor, mid).state == "down"
        uptime.run_due(db, force_ids=[mid])
        assert db.get(Monitor, mid).state == "up"
        titles = [a.title for a in db.query(Alert).filter(Alert.kind == "uptime")]
    assert "Nextcloud ist nicht erreichbar" in titles and "Nextcloud ist wieder erreichbar" in titles
    rows = client.get("/api/monitors", headers=admin).json()
    mon = next(m for m in rows if m["id"] == mid)
    assert mon["uptime_24h"] == round(100 / 3, 2) and len(mon["history"]) == 48
    assert client.post("/api/monitors", headers=admin, json={"name": "x", "url": "ftp://x"}).status_code == 422


class FakePorkbun:
    def __init__(self):
        self.recs = {"example.de": [{"id": "1", "name": "example.de", "type": "A", "content": "198.51.100.1", "ttl": "600"},
                                    {"id": "2", "name": "www.example.de", "type": "CNAME", "content": "example.de", "ttl": "600"}]}
        self.next = 10

    def __call__(self, path, body=None, timeout=20, base=None):
        body = body or {}
        parts = path.strip("/").split("/")
        if parts[0] == "ping":
            return {"status": "SUCCESS", "yourIp": "84.130.20.50"}
        if parts[:2] == ["domain", "listAll"]:
            return {"status": "SUCCESS", "domains": [{"domain": "example.de", "status": "ACTIVE"}]}
        domain = parts[2]
        recs = self.recs[domain]
        if parts[1] == "retrieve":
            return {"status": "SUCCESS", "records": recs}
        if parts[1] == "create":
            self.next += 1
            fq = f"{body['name']}.{domain}" if body.get("name") else domain
            recs.append({"id": str(self.next), "name": fq, "type": body["type"], "content": body["content"], "ttl": body["ttl"]})
            return {"status": "SUCCESS", "id": self.next}
        if parts[1] == "editByNameType":
            name = parts[4] if len(parts) > 4 else ""
            fq = f"{name}.{domain}" if name else domain
            for r in recs:
                if r["name"] == fq and r["type"] == parts[3]:
                    r["content"] = body["content"]
            return {"status": "SUCCESS"}
        if parts[1] == "delete":
            self.recs[domain] = [r for r in recs if r["id"] != parts[3]]
            return {"status": "SUCCESS"}
        raise AssertionError(path)


def test_dns_and_dyndns(client, admin, monkeypatch):
    fake = FakePorkbun()
    monkeypatch.setattr(porkbun, "_post", fake)
    monkeypatch.setattr("app.scheduler.trigger", lambda name: True)
    r = client.put("/api/admin/settings", headers=admin, json={"values": {"porkbun_api_key": "pk1_x", "porkbun_secret_key": "sk1_x"}})
    assert r.json()["porkbun_ready"]
    st = client.get("/api/dns/status", headers=admin).json()
    assert st["domains"] == ["example.de"] and st["configured"]
    recs = client.get("/api/dns/records/example.de", headers=admin).json()["records"]
    assert {r["name"] for r in recs} == {"", "www"}
    assert client.get("/api/dns/records/fremd.de", headers=admin).status_code == 404

    # Neuer A-Record mit öffentlicher IP und DynDNS
    r = client.post("/api/dns/records/example.de", headers=admin, json={"name": "cloud", "type": "A", "dyn": True})
    assert r.status_code == 201
    assert any(x["name"] == "cloud.example.de" and x["content"] == "84.130.20.50" for x in fake.recs["example.de"])
    # Hauptdomain zeigt noch auf eine alte IP: DynDNS zieht sie nach
    client.put("/api/dns/dyn", headers=admin, json={"domain": "example.de", "name": "", "type": "A", "enabled": True})
    res = client.post("/api/dns/dyndns/run", headers=admin).json()
    assert res["ip"] == "84.130.20.50" and "example.de" in res["updated"]
    assert fake.recs["example.de"][0]["content"] == "84.130.20.50"
    assert client.post("/api/dns/records/example.de", headers=admin, json={"name": "bad name", "type": "A", "content": "1.2.3.4"}).status_code == 422

    # Abgleich mit dem Proxy Manager
    monkeypatch.setattr("app.npm.proxy_hosts", lambda: [
        {"id": 1, "domains": ["cloud.example.de"], "forward": "http://10.0.0.2:80", "enabled": True, "ssl": True},
        {"id": 2, "domains": ["jelly.example.de", "media.example.de"], "forward": "http://10.0.0.3:8096", "enabled": True, "ssl": True},
        {"id": 3, "domains": ["foo.anders.org"], "forward": "http://10.0.0.4", "enabled": True, "ssl": False}])
    ov = client.get("/api/dns/npm", headers=admin).json()
    status = {i["fqdn"]: i["status"] for i in ov["items"]}
    assert status == {"cloud.example.de": "ok", "jelly.example.de": "missing", "media.example.de": "missing", "foo.anders.org": "foreign"}
    r = client.post("/api/dns/npm/create", headers=admin, json={"fqdns": ["jelly.example.de"]}).json()
    assert r["created"][0]["type"] == "A" and not r["errors"]
    rid = next(x["id"] for x in fake.recs["example.de"] if x["name"] == "jelly.example.de")
    assert client.delete(f"/api/dns/records/example.de/{rid}", headers=admin).status_code == 204
    client.put("/api/admin/settings", headers=admin, json={"values": {"porkbun_api_key": "", "porkbun_secret_key": ""}})


def test_npm_sync_creates_monitors_and_sites(client, admin, monkeypatch):
    from app import dns as dns_mod
    monkeypatch.setattr("app.npm.proxy_hosts", lambda: [
        {"id": 1, "domains": ["home.example.de"], "forward": "http://10.0.0.5:8123", "enabled": True, "ssl": True}])
    with SessionLocal() as db:
        out = dns_mod.sync_from_npm(db)
    assert out["monitors"] == 1 and out["sites"] == 1
    sites = client.get("/api/security/sites", headers=admin).json()["items"]
    assert any(s["host"] == "home.example.de" and s["source"] == "npm" for s in sites)
    mons = client.get("/api/monitors", headers=admin).json()
    m = next(m for m in mons if m["url"] == "https://home.example.de/")
    assert client.delete(f"/api/monitors/{m['id']}", headers=admin).status_code == 409


def test_alert_mail_batching(client, admin, monkeypatch):
    sent = []
    monkeypatch.setattr(notify, "send_email", lambda to, title, body: sent.append((to, title, body)))
    monkeypatch.setattr(notify, "smtp_configured", lambda: True)
    with SessionLocal() as db:
        db.query(Alert).delete()
        db.commit()
        notify.raise_alert(db, "warn", "test", "Erste Warnung", dedupe_key="t1")
        assert notify.raise_alert(db, "warn", "test", "Doppelt", dedupe_key="t1") is None
        notify.raise_alert(db, "info", "test", "Nur Hinweis")
        assert notify.send_pending(db) == 0  # Warnungen werden kurz gesammelt
        assert notify.send_pending(db, now=datetime.utcnow() + timedelta(minutes=4)) == 1
        assert len(sent) == 1 and sent[0][1] == "NetworkHelper: Erste Warnung" and "admin@example.de" in sent[0][0]
        notify.raise_alert(db, "crit", "test", "Sofort")
        assert notify.send_pending(db) == 1  # kritisch sofort
        assert db.query(Alert).filter(Alert.sent_at.is_(None)).count() == 0


def test_overview_and_ports(client, admin, monkeypatch):
    from app import portscan
    from app.models import PortFinding
    with SessionLocal() as db:
        now = datetime.utcnow()
        db.add_all([PortFinding(target="84.130.20.50", port=443, source="scan", open=True, first_seen=now, last_seen=now),
                    PortFinding(target="84.130.20.50", port=8006, source="scan", open=True, first_seen=now, last_seen=now, service="Proxmox VE")])
        db.commit()
    ov = client.get("/api/overview", headers=admin).json()
    texts = [r["text"] for r in ov["security"]["reasons"]]
    assert any("8006" in t for t in texts) and not any("Port 443" in t for t in texts)
    assert ov["access"]["total"] >= 7 and len(ov["access"]["series"]) == 25
    # Jeder Zugriff landet in genau einem Balken des Verlaufs
    assert sum(s["2"] + s["3"] + s["4"] + s["5"] for s in ov["access"]["series"]) == ov["access"]["total"]
    for rng in ("1h", "24h", "7d", "30d"):
        s = client.get(f"/api/access/summary?range={rng}", headers=admin).json()
        assert sum(b["2"] + b["3"] + b["4"] + b["5"] for b in s["series"]) == s["total"], rng
    r = client.put("/api/security/ports/expected", headers=admin, json={"port": 8006, "expected": True})
    assert 8006 in r.json()["expected"] and 443 in r.json()["expected"]
    ports = client.get("/api/security/ports", headers=admin).json()
    assert all(p["expected"] for p in ports["items"])
    assert 8006 in portscan.RISKY


def test_admin_health_and_settings(client, admin):
    h = client.get("/api/admin/health", headers=admin).json()
    assert {c["key"] for c in h["checks"]} >= {"db", "disk", "mail", "geoip"}
    assert any(j["name"] == "portscan" for j in h["jobs"])
    r = client.put("/api/admin/settings", headers=admin, json={"values": {"scan_ports": "22, 80-90"}})
    assert r.status_code == 200 and r.json()["fields"]["scan_ports"]["value"] == "22, 80-90"
    assert client.put("/api/admin/settings", headers=admin, json={"values": {"scan_ports": "abc"}}).status_code == 422
    assert client.get("/api/agent/files/install.sh").status_code == 200
    assert client.get("/api/agent/files/../main.py").status_code == 404
    with SessionLocal() as db:
        assert db.query(Incident).count() >= 1


def test_auto_block_for_ongoing_attack(client, admin):
    token = client.post("/api/agents", headers=admin, json={"name": "dritter"}).json()["token"]
    ah = {"Authorization": f"Bearer {token}"}
    client.post("/api/agent/logs", json={"lines": [line("89.248.165.77", 401, "/login") for _ in range(22)]}, headers=ah)
    settings.auto_block = False
    with SessionLocal() as db:
        detect.run(db)
        assert detect.is_blocked(db, "89.248.165.77") is None
    client.post("/api/agent/logs", json={"lines": [line("89.248.165.77", 401, "/login") for _ in range(3)]}, headers=ah)
    settings.auto_block = True
    try:
        with SessionLocal() as db:
            detect.run(db)
            assert detect.is_blocked(db, "89.248.165.77") is not None
            assert db.query(Alert).filter(Alert.title == "89.248.165.77 automatisch gesperrt").count() == 1
    finally:
        settings.auto_block = False


def test_onboarding_state(client, admin):
    me = client.get("/api/me", headers=admin).json()
    assert me["onboarding_done"] is False and me["tour_done"] is False and me["hints_hidden"] == []
    me = client.put("/api/me/onboarding", headers=admin, json={"onboarding_done": True, "hide_hint": "intro:access"}).json()
    assert me["onboarding_done"] and me["hints_hidden"] == ["intro:access"]
    me = client.put("/api/me/onboarding", headers=admin, json={"hide_hint": "intro:access"}).json()
    assert me["hints_hidden"] == ["intro:access"]  # nicht doppelt
    me = client.put("/api/me/onboarding", headers=admin, json={"tour_done": True, "show_hints": True}).json()
    assert me["tour_done"] and me["hints_hidden"] == []
    st = client.get("/api/setup/status", headers=admin).json()
    assert st["agents"]["total"] >= 1 and {"npm", "porkbun", "smtp", "monitors"} <= set(st)


def test_inside_only_port_barely_counts(client, admin):
    from app import state
    from app.models import PortFinding
    with SessionLocal() as db:
        now = datetime.utcnow()
        db.add(PortFinding(target="84.130.20.50", port=5060, source="scan", open=True, first_seen=now, last_seen=now, service="SIP (Internet-Telefonie)"))
        state.put(db, "portscan_last", {"targets": ["84.130.20.50"], "shodan": {"ports": [80, 443], "vulns": []}})
    ports = client.get("/api/security/ports", headers=admin).json()["items"]
    sip = next(p for p in ports if p["port"] == 5060)
    assert sip["outside"] == "no"
    reasons = client.get("/api/overview", headers=admin).json()["security"]["reasons"]
    r = next(r for r in reasons if "5060" in r["text"])
    assert r["points"] == 2 and "nur aus dem Heimnetz" in r["text"]


def test_router_guides_settings(client, admin):
    assert client.get("/api/security/ports", headers=admin).json()["router"] == "fritzbox"
    assert client.put("/api/admin/settings", headers=admin, json={"values": {"router_type": "other"}}).status_code == 200
    assert client.get("/api/security/ports", headers=admin).json()["router"] == "other"
    assert client.put("/api/admin/settings", headers=admin, json={"values": {"router_type": "speedport"}}).status_code == 422
    client.put("/api/admin/settings", headers=admin, json={"values": {"router_type": "fritzbox"}})
    me = client.put("/api/me/onboarding", headers=admin, json={"hide_hint": "router:update"}).json()
    assert "router:update" in me["hints_hidden"]
    me = client.put("/api/me/onboarding", headers=admin, json={"unhide_hint": "router:update"}).json()
    assert "router:update" not in me["hints_hidden"]


def test_map_and_visitors(client, admin):
    from app.models import AccessEvent
    now = datetime.utcnow()
    rows = [("91.12.34.56", "DE", "Deutsche Telekom AG", "Mozilla/5.0 (Windows NT 10.0) Chrome/130 Safari/537.36", 200, "/", 4),
            ("162.142.125.9", "US", "Censys, Inc.", "Mozilla/5.0 (compatible; CensysInspect/1.1)", 404, "/", 3),
            ("45.148.10.1", "NL", "Stark Industries", "zgrab/0.x", 404, "/.env", 6),
            ("192.168.1.50", None, "Heimnetz", "Mozilla/5.0", 200, "/", 2)]
    with SessionLocal() as db:
        for ip, cc, org, ua, status, path, n in rows:
            for i in range(n):
                db.add(AccessEvent(ts=now - timedelta(minutes=i), host="cloud.example.de", method="GET", path=path, status=status,
                                   bytes=1, ip=ip, country=cc, as_org=org, user_agent=ua))
        db.add(Incident(ip="45.148.10.1", kind="scanner", severity="warn", count=6, first_seen=now, last_seen=now))
        db.commit()
    m = client.get("/api/access/map?range=24h", headers=admin)
    assert m.status_code == 200, m.text
    m = m.json()
    by_cc = {p["country"]: p for p in m["points"]}
    assert set(by_cc) == {"DE", "US", "NL"}  # Heimnetz nicht auf der Karte
    assert by_cc["NL"]["group"] == "attack" and by_cc["US"]["group"] == "noise" and by_cc["DE"]["group"] == "friendly"
    assert sum(p["count"] for p in m["points"]) == 13 and m["countries"][0]["country"] == "NL"
    v = client.get("/api/access/visitors?range=24h", headers=admin).json()
    cats = {c["category"]: c for c in v["categories"]}
    assert cats["research"]["who"] == ["Censys"] and cats["scan_attack"]["count"] == 6 and cats["home"]["ips"] == 1
    assert v["categories"][0]["group"] == "attack"
    only = client.get("/api/access/visitors?range=24h&category=visitor", headers=admin).json()["items"]
    assert [i["ip"] for i in only] == ["91.12.34.56"]
    d = client.get("/api/access/ip/162.142.125.9", headers=admin).json()
    assert d["reason"]["category"] == "research" and d["location"]["country"] == "US"
    assert client.get("/api/access/map?range=99d", headers=admin).status_code == 422


def test_exposure_selfcheck(client, admin, monkeypatch):
    from app import exposure
    from app.models import AccessEvent, Exposure, SiteCheck
    now = datetime.utcnow()
    page = "<!doctype html><html><title>App</title><body>" + "y" * 800 + "</body></html>"
    files = {"/.env": ("APP_KEY=base64:xyz\nDB_PASSWORD=geheim\nMAIL_PASSWORD=x\n", "text/plain"),
             "/backup.tar": ("\x00binär\x00daten" * 20, "application/x-tar")}

    def fake_get(self, host, path):
        if host != "leaky.example.de":
            return {"status": 404, "text": "", "raw": b"", "ctype": "", "location": ""}
        text, ctype = files.get(path, (page, "text/html"))
        return {"status": 200, "text": text, "raw": text.encode(), "ctype": ctype, "location": ""}
    monkeypatch.setattr(exposure.Fetcher, "get", fake_get)
    with SessionLocal() as db:
        db.add_all([SiteCheck(host="leaky.example.de", enabled=True), SiteCheck(host="tidy.example.de", enabled=True)])
        for path, ip in [("/.env", "45.9.9.1"), ("/.env", "45.9.9.2"), ("/backup.tar", "45.9.9.3"), ("/wp-login.php", "45.9.9.3")]:
            db.add(AccessEvent(ts=now, host="leaky.example.de", method="GET", path=path, status=200, bytes=90, ip=ip, user_agent="zgrab"))
        db.add(AccessEvent(ts=now, host="leaky.example.de", method="GET", path="/.git/config", status=200, bytes=90, ip="192.168.1.9",
                           user_agent=exposure.USER_AGENT))  # eigene Prüfung zählt nicht als Angriff
        db.commit()
        exposure.run(db)
        rows = {e.path: e for e in db.query(Exposure).all()}
    assert rows["/.env"].result == "exposed" and rows["/.env"].severity == "crit" and rows["/.env"].attacked == 2
    assert "geheim" not in rows["/.env"].evidence and "DB_PASSWORD=•••" in rows["/.env"].evidence
    assert rows["/backup.tar"].result == "unclear"
    assert "/wp-login.php" not in rows and "/.git/config" not in rows  # liefert nur die Startseite
    d = client.get("/api/security/exposure", headers=admin).json()
    hits = {h["path"]: h for h in d["log_hits"]}
    assert hits["/wp-login.php"]["result"] == "catchall" and hits["/.env"]["result"] == "exposed" and "/.git/config" not in hits
    assert {h["host"] for h in d["hosts"]} >= {"leaky.example.de", "tidy.example.de"}
    st = client.get("/api/overview", headers=admin).json()
    assert any(r["area"] == "exposure" and r["level"] == "crit" for r in st["security"]["reasons"])
    with SessionLocal() as db:
        assert db.query(Alert).filter(Alert.kind == "exposure").count() == 1
    # behoben: Datei weg -> Eintrag gilt als erledigt
    files.pop("/.env")
    with SessionLocal() as db:
        exposure.run(db)
        assert db.query(Exposure).filter(Exposure.path == "/.env").one().fixed_at is not None
    eid = next(f["id"] for f in d["findings"] if f["path"] == "/backup.tar")
    assert client.put(f"/api/security/exposure/{eid}", headers=admin, json={"acknowledged": True}).json()["acknowledged"] is True


def test_two_factor_flow(client, admin, monkeypatch):
    import time as _time
    from app import totp
    r = client.post("/api/auth/register", json={"email": "zwei@example.de", "password": "geheim1234"})
    if r.status_code != 201:  # Registrierung evtl. nur per Einladung
        inv = client.post("/api/admin/invites", headers=admin).json()["code"]
        r = client.post("/api/auth/register", json={"email": "zwei@example.de", "password": "geheim1234", "invite": inv})
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.get("/api/me/2fa", headers=h).json()["enabled"] is False
    assert client.post("/api/me/2fa/setup", headers=h, json={"password": "falsch"}).status_code == 403
    s = client.post("/api/me/2fa/setup", headers=h, json={"password": "geheim1234"}).json()
    secret = s["secret"].replace(" ", "")
    assert s["uri"].startswith("otpauth://totp/NetworkHelper:") and "<svg" in s["qr_svg"]
    assert client.post("/api/me/2fa/enable", headers=h, json={"code": "000000"}).status_code == 422
    now = [_time.time()]
    monkeypatch.setattr(totp.time, "time", lambda: now[0])
    code = lambda: totp.code_at(secret, totp.current_step())  # noqa: E731
    en = client.post("/api/me/2fa/enable", headers=h, json={"code": code()}).json()
    recovery = en["recovery_codes"]
    assert len(recovery) == 10 and en["status"]["enabled"] and en["status"]["recovery_left"] == 10
    assert client.get("/api/me", headers=h).status_code == 401  # alte Sitzung abgemeldet
    h = {"Authorization": f"Bearer {en['access_token']}"}
    assert client.get("/api/me", headers=h).json()["two_factor"] is True

    # Anmeldung: erst Passwort, dann Code
    step1 = client.post("/api/auth/login", json={"email": "zwei@example.de", "password": "geheim1234"}).json()
    assert step1["two_factor"] is True and "access_token" not in step1
    ch = step1["challenge"]
    assert client.get("/api/me", headers={"Authorization": f"Bearer {ch}"}).status_code == 401  # kein Zugang ohne Code
    assert client.post("/api/auth/login/2fa", json={"challenge": ch, "code": "123456"}).status_code == 401
    assert client.post("/api/auth/login/2fa", json={"challenge": ch, "code": code()}).status_code == 401  # schon bei enable benutzt
    now[0] += 30
    ok = client.post("/api/auth/login/2fa", json={"challenge": ch, "code": code()})
    assert ok.status_code == 200 and ok.json()["access_token"]
    # Wiederherstellungscode, nur einmal
    assert client.post("/api/auth/login/2fa", json={"challenge": ch, "code": recovery[0]}).status_code == 200
    assert client.post("/api/auth/login/2fa", json={"challenge": ch, "code": recovery[0]}).status_code == 401
    with SessionLocal() as db:
        assert db.query(Alert).filter(Alert.kind == "account").count() >= 1
    # Admin sieht den Status und kann zurücksetzen
    users = client.get("/api/admin/users", headers=admin).json()
    uid = next(u["id"] for u in users if u["email"] == "zwei@example.de")
    assert next(u for u in users if u["id"] == uid)["two_factor"] is True
    # Pflicht für alle: Konto ohne 2FA kommt nur noch an die Einrichtung
    r = client.put("/api/admin/settings", headers=admin, json={"values": {"two_factor_required": True}})
    assert r.status_code == 422 and "aussperrst" not in r.text and "eigene" in r.text  # Admin ohne 2FA würde sich aussperren
    monkeypatch.setattr(settings, "two_factor_required", True)
    assert client.get("/api/overview", headers=admin).status_code == 403
    assert client.get("/api/me", headers=admin).json()["must_setup_2fa"] is True
    assert client.get("/api/me/2fa", headers=admin).status_code == 200
    assert client.get("/api/overview", headers=h).status_code == 200  # Konto mit 2FA arbeitet normal
    monkeypatch.setattr(settings, "two_factor_required", False)
    assert client.get("/api/overview", headers=admin).status_code == 200
    reasons = client.get("/api/overview", headers=admin).json()["security"]["reasons"]
    assert any(r["area"] == "account" for r in reasons)
    r = client.delete(f"/api/admin/users/{uid}/2fa", headers=admin).json()
    assert r["two_factor"] is False
    assert client.post("/api/auth/login", json={"email": "zwei@example.de", "password": "geheim1234"}).json()["access_token"]


def test_cookie_session(client, admin):
    r = client.post("/api/auth/register", json={"email": "keks@example.de", "password": "geheim1234"})
    if r.status_code != 201:
        inv = client.post("/api/admin/invites", headers=admin).json()["code"]
        r = client.post("/api/auth/register", json={"email": "keks@example.de", "password": "geheim1234", "invite": inv})
    client.cookies.clear()
    r = client.post("/api/auth/login", json={"email": "keks@example.de", "password": "geheim1234"})
    sc = r.headers["set-cookie"]
    assert "nh_session=" in sc and "HttpOnly" in sc and "samesite=strict" in sc.lower() and "Path=/api" in sc
    assert client.get("/api/me").json()["email"] == "keks@example.de"  # nur mit Cookie
    # Ändernde Anfragen per Cookie brauchen den App-Kopf (Schutz gegen fremde Formulare)
    assert client.put("/api/me/alerts", json={"alert_email": True}).status_code == 403
    assert client.put("/api/me/alerts", json={"alert_email": True}, headers={"X-NH-Request": "1"}).status_code == 200
    assert client.post("/api/auth/logout", headers={"X-NH-Request": "1"}).status_code == 204
    assert client.get("/api/me").status_code == 401
    # Alte, im Browser gespeicherte Anmeldung wird ins Cookie übernommen
    tok = client.post("/api/auth/login", json={"email": "keks@example.de", "password": "geheim1234"}).json()["access_token"]
    client.cookies.clear()
    assert "nh_session=" in client.post("/api/auth/session", headers={"Authorization": f"Bearer {tok}"}).headers["set-cookie"]
    assert client.get("/api/me").status_code == 200


def test_app_versions_endpoint(client, admin, monkeypatch):
    from app import appversions as av
    from app.models import SiteCheck
    with SessionLocal() as db:
        db.merge(SiteCheck(host="jelly.example.de", enabled=True))
        db.merge(SiteCheck(host="cloud2.example.de", enabled=True))
        db.commit()
    found = {"jelly.example.de": {"app": "jellyfin", "version": "10.9.10"}, "cloud2.example.de": {"app": "nextcloud", "version": "30.0.2"}}
    monkeypatch.setattr(av, "detect_host", lambda host, client: found.get(host))
    monkeypatch.setattr(av, "npm_version", lambda: None)

    def gh(path):
        if path.endswith("/releases/latest"):
            return {"tag_name": "v10.10.3" if "jellyfin" in path else "v30.0.2", "html_url": "https://github.com/x"}
        if "jellyfin" in path:
            return [{"ghsa_id": "GHSA-abcd", "summary": "Pfad-Traversal", "severity": "high", "html_url": "https://g/a", "cve_id": "CVE-2026-1",
                     "vulnerabilities": [{"package": {"name": "jellyfin"}, "vulnerable_version_range": "< 10.9.11", "patched_versions": "10.9.11"}]}]
        return []
    monkeypatch.setattr(av, "_gh", gh)
    with SessionLocal() as db:
        av.run(db)
    d = client.get("/api/security/apps", headers=admin).json()
    items = {i["host"]: i for i in d["items"]}
    assert items["jelly.example.de"]["status"] == "vulnerable" and items["jelly.example.de"]["advisories"][0]["id"] == "GHSA-abcd"
    assert items["cloud2.example.de"]["status"] == "current"
    with SessionLocal() as db:
        assert db.query(Alert).filter(Alert.kind == "apps").count() == 1
    reasons = client.get("/api/overview", headers=admin).json()["security"]["reasons"]
    assert any(r["area"] == "apps" and r["level"] == "crit" for r in reasons)


def _new_agent(client, admin, name):
    r = client.post("/api/agents", headers=admin, json={"name": name})
    return {"Authorization": f"Bearer {r.json()['token']}"}, r.json()["id"]


def test_host_watch(client, admin):
    ah, aid = _new_agent(client, admin, "Proxmox-Host")
    st = lambda listening: client.post("/api/agent/state", headers=ah, json={  # noqa: E731
        "hostname": "pve", "version": "1.1.0", "info": {}, "established": [], "listening": listening})
    r = st([{"proto": "tcp", "addr": "0.0.0.0", "port": 22, "process": "sshd"}]).json()
    assert r["agent_version"] and r["http_conf_hash"] is None
    base = {"users": [{"name": "root", "uid": 0, "shell": "/bin/bash", "admin": True}],
            "files": {"/etc/passwd": "a", "/root/.ssh/authorized_keys": "b", "/etc/crontab": "c"}, "proxmox": True,
            "logins": [{"ts": 1729700000, "user": "root", "ip": "192.168.1.5", "method": "publickey", "service": "ssh"}], "failures": {}}
    assert client.post("/api/agent/watch", headers=ah, json=base).status_code == 200
    w = client.get(f"/api/agents/{aid}/watch", headers=admin).json()
    assert w["active"] and w["proxmox"] and w["open"] == [] and len(w["logins"]) == 1  # erster Bericht: nur merken
    # Änderungen
    nxt = {**base, "users": base["users"] + [{"name": "eve", "uid": 1001, "shell": "/bin/bash", "admin": True}],
           "files": {**base["files"], "/root/.ssh/authorized_keys": "NEU", "/etc/cron.d/x": "d"},
           "logins": [{"ts": 1729700100, "user": "root", "ip": "45.9.9.9", "method": "password", "service": "ssh"}],
           "failures": {"45.9.9.10": 25}}
    client.post("/api/agent/watch", headers=ah, json=nxt)
    st([{"proto": "tcp", "addr": "0.0.0.0", "port": 22, "process": "sshd"}, {"proto": "tcp", "addr": "0.0.0.0", "port": 4444, "process": "nc"},
        {"proto": "tcp", "addr": "0.0.0.0", "port": 51000, "process": "x"}])
    w = client.get(f"/api/agents/{aid}/watch", headers=admin).json()
    kinds = {e["kind"]: e for e in w["open"]}
    assert kinds["user_new"]["severity"] == "crit" and "eve" in kinds["user_new"]["title"]
    assert kinds["file_changed"]["severity"] == "crit" and "authorized_keys" in kinds["file_changed"]["detail"]
    assert kinds["file_new"]["severity"] == "warn"
    assert kinds["login"]["severity"] == "crit" and "45.9.9.9" in kinds["login"]["title"]
    assert "login_fail" in kinds and "port_new" in kinds and "4444" in kinds["port_new"]["title"]
    assert not any("51000" in e["title"] for e in w["open"])  # flüchtige Ports nicht melden
    with SessionLocal() as db:
        assert db.query(Alert).filter(Alert.kind == "host").count() >= 5
    reasons = client.get("/api/overview", headers=admin).json()["security"]["reasons"]
    assert any(r["area"] == "host" and r["level"] == "crit" for r in reasons)
    assert client.put(f"/api/watch/events/{kinds['user_new']['id']}", headers=admin, json={"acknowledged": True}).json()["acknowledged"]
    assert client.post(f"/api/agents/{aid}/watch/ack-all", headers=admin).json()["acknowledged"] >= 4
    assert client.get(f"/api/agents/{aid}/watch", headers=admin).json()["open"] == []
    # gleicher Stand noch einmal (ohne neue Anmeldungen): nichts Neues
    client.post("/api/agent/watch", headers=ah, json={**nxt, "logins": [], "failures": {}})
    assert client.get(f"/api/agents/{aid}/watch", headers=admin).json()["open"] == []


def test_geo_rules_and_agent_conf(client, admin, monkeypatch):
    from app import geoblock
    from app.models import AccessEvent
    now = datetime.utcnow()
    with SessionLocal() as db:
        for ip, cc, ua, n in [("91.1.1.1", "DE", "Mozilla/5.0 (Windows NT 10.0) Chrome/130 Safari/537.36", 5), ("45.2.2.2", "RU", "zgrab", 7),
                              ("83.3.3.3", "ES", "Nextcloud-android/3.29", 4)]:
            for i in range(n):
                db.add(AccessEvent(ts=now - timedelta(minutes=i), host="geo.example.de", method="GET", path="/", status=200, bytes=1,
                                   ip=ip, country=cc, as_org="X", user_agent=ua))
        db.add(AccessEvent(ts=now, host="geo.example.de", method="GET", path="/.well-known/acme-challenge/t", status=200, bytes=1,
                           ip="23.1.1.1", country="US", as_org="Let's Encrypt", user_agent="LE"))
        db.commit()
    p = client.post("/api/security/geo/preview", headers=admin, json={"host": "geo.example.de", "countries": ["DE"]}).json()
    assert p["total"] == 16 and p["blocked"] == 11 and p["countries"][0]["country"] == "RU"
    assert [a["who"] for a in p["affected_users"]] == ["Nextcloud"]  # eigene Nutzerin im Urlaub wäre betroffen
    assert client.post("/api/security/geo/rules", headers=admin, json={"host": "ungültig host", "countries": ["DE"]}).status_code == 422
    r = client.post("/api/security/geo/rules", headers=admin, json={"host": "geo.example.de", "countries": ["de", "es"]})
    assert r.status_code == 201 and r.json()["countries"] == ["DE", "ES"]
    assert client.post("/api/security/geo/rules", headers=admin, json={"host": "geo.example.de", "countries": ["DE"]}).status_code == 409
    monkeypatch.setattr(geoblock, "country_networks", lambda cc: {"DE": ["5.0.0.0/16"], "ES": ["83.0.0.0/11"]})
    geoblock.invalidate()
    ah, _ = _new_agent(client, admin, "NPM-Geo")
    res = client.post("/api/agent/state", headers=ah, json={"hostname": "npm", "version": "1.1.0", "info": {}, "established": [], "listening": []}).json()
    assert res["http_conf_hash"] and "return 444" in res["server_snippet"]
    conf = client.get("/api/agent/http-conf", headers=ah).text
    assert "5.0.0.0/16 DE;" in conf and "geo\\.example\\.de\\|(DE|ES|LAN)$" in conf
    assert client.get("/api/agent/http-conf").status_code == 401
    rid = r.json()["id"]
    client.delete(f"/api/security/geo/rules/{rid}", headers=admin)
    res2 = client.post("/api/agent/state", headers=ah, json={"hostname": "npm", "version": "1.1.0", "info": {}, "established": [], "listening": []}).json()
    assert res2["http_conf_hash"] is None and res2["blocklist_hash"] != res["blocklist_hash"]
    g = client.get("/api/security/geo", headers=admin).json()
    assert {f["key"] for f in g["feeds"]} == {"spamhaus", "firehol"} and g["rules"] == []


def test_weekly_report(client, admin, monkeypatch):
    from app import report
    from app.config import settings as cfg
    p = client.get("/api/admin/report/preview", headers=admin).json()
    assert p["title"].startswith("NetworkHelper Wochenbericht") and "Sicherheit:" in p["body"] and "Die letzte Woche" in p["body"]
    sent = []
    monkeypatch.setattr(report.notify, "send_email", lambda to, t, b: sent.append((to, t)))
    monkeypatch.setattr(report.notify, "smtp_configured", lambda: True)
    monkeypatch.setattr(cfg, "weekly_report", True)
    monkeypatch.setattr(cfg, "weekly_report_day", 0)
    monkeypatch.setattr(cfg, "weekly_report_hour", 8)
    monday_7 = datetime(2026, 10, 26, 6, 0)  # 07:00 Berlin (MEZ): noch zu früh
    monday_9 = datetime(2026, 10, 26, 8, 30)  # 09:30 Berlin
    with SessionLocal() as db:
        assert report.run(db, now=datetime(2026, 10, 27, 8, 30)) is False  # Dienstag
        assert report.run(db, now=monday_7) is False
        assert report.run(db, now=monday_9) is True
        assert report.run(db, now=monday_9 + timedelta(hours=2)) is False  # nur einmal pro Woche
    assert len(sent) == 1 and "admin@example.de" in sent[0][0]


def test_domain_protection(client, admin, monkeypatch):
    from app import porkbun
    recs = {"example.de": [{"id": "1", "name": "", "type": "A", "content": "1.2.3.4"}]}
    created = []
    monkeypatch.setattr(porkbun, "configured", lambda: True)
    monkeypatch.setattr(porkbun, "managed_domains", lambda: ["example.de"])
    monkeypatch.setattr(porkbun, "records", lambda d: recs[d])

    def create(domain, name, rtype, content, ttl=600, notes=None, prio=None):
        created.append((name, rtype, content, prio))
        recs[domain].append({"id": str(len(recs[domain]) + 1), "name": name, "type": rtype, "content": content})
        return "x"
    monkeypatch.setattr(porkbun, "create", create)
    d = client.get("/api/dns/protection?refresh=true", headers=admin).json()
    assert d["domains"][0]["open"] == 2  # SPF und DMARC (Null-MX und CAA sind nur Empfehlungen)
    reasons = client.get("/api/overview", headers=admin).json()["security"]["reasons"]
    assert sum(1 for r in reasons if r["area"] == "domain") == 2
    for key in ("spf", "dmarc", "null_mx", "caa"):
        assert client.post(f"/api/dns/protection/example.de/{key}", headers=admin).status_code == 201
    assert ("", "MX", ".", "0") in created and ("_dmarc", "TXT", "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s", None) in created
    assert client.post("/api/dns/protection/example.de/spf", headers=admin).status_code == 409  # schon gesetzt
    assert client.post("/api/dns/protection/fremd.de/spf", headers=admin).status_code == 404
    assert client.get("/api/dns/protection", headers=admin).json()["domains"][0]["ok"] is True


def test_old_ip_findings_disappear(client, admin, monkeypatch):
    from app import portscan, publicip, state
    from app.models import PortFinding
    now = datetime.utcnow()
    with SessionLocal() as db:
        state.put(db, "public_ip", {"ip": "79.208.166.153", "source": "test", "since": now.isoformat()})
        db.add(PortFinding(target="84.133.221.52", port=8089, source="shodan", service="TR-069", first_seen=now, last_seen=now, open=True))
        db.add(PortFinding(target="79.208.166.153", port=443, source="scan", service="HTTPS", first_seen=now, last_seen=now, open=True))
        db.commit()
    items = client.get("/api/security/ports", headers=admin).json()["items"]
    assert {i["target"] for i in items} == {"79.208.166.153"}  # alte IP sofort ausgeblendet
    monkeypatch.setattr(publicip, "current", lambda db, **kw: "79.208.166.153")
    monkeypatch.setattr(portscan, "scan_host", lambda host, ports: _done({443: None}))
    monkeypatch.setattr(portscan, "shodan_lookup", lambda ip: {"ports": [], "unknown": True})
    monkeypatch.setattr(portscan.settings, "scan_targets", "")
    with SessionLocal() as db:
        res = portscan.run(db)
        assert "84.133.221.52" in res["removed_old"]
        assert db.query(PortFinding).filter(PortFinding.target == "84.133.221.52").count() == 0
    item = next(i for i in client.get("/api/security/ports", headers=admin).json()["items"] if i["port"] == 443)
    assert item["outside"] == "unknown"  # Shodan kennt die neue Adresse noch nicht: nicht „nur von innen“


async def _done(value):
    return value


def test_own_public_ip_is_never_an_incident(client, admin):
    from app import detect, notify, state
    from app.models import AccessEvent, BlockEntry
    now = datetime.utcnow()
    with SessionLocal() as db:
        state.put(db, "public_ip", {"ip": "79.208.166.200", "source": "test", "since": (now - timedelta(hours=1)).isoformat()})
        notify.raise_alert(db, "info", "ip", "Neue öffentliche IP: 79.208.166.200", "Vorher: 84.133.221.99")
        db.commit()
        # Alte Vorfälle und eine automatische Sperre der früheren eigenen IP
        db.add(Incident(ip="84.133.221.99", kind="flood", severity="warn", count=1500, first_seen=now - timedelta(hours=5), last_seen=now - timedelta(hours=3)))
        db.add(BlockEntry(cidr="84.133.221.99", reason="Automatisch", auto=True, created_by="automatisch"))
        for i in range(80):
            db.add(AccessEvent(ts=now - timedelta(seconds=i), host="cloud.example.de", method="GET", path=f"/nicht-da-{i}", status=404, bytes=1,
                               ip="79.208.166.200", country="DE", as_org="Deutsche Telekom AG", user_agent="Nextcloud-android"))
        db.commit()
        detect.run(db)
        assert db.query(Incident).filter(Incident.ip == "79.208.166.200").count() == 0
        assert detect.forget_own(db) == {"incidents": 1, "blocks": 1}
        assert db.query(BlockEntry).filter(BlockEntry.cidr == "84.133.221.99").count() == 0
    v = client.get("/api/access/visitors?range=24h", headers=admin).json()
    me = next(i for i in v["items"] if i["ip"] == "79.208.166.200")
    assert me["category"] == "self"


def test_cannot_block_own_ip(client, admin):
    from app import state
    with SessionLocal() as db:
        state.put(db, "public_ip", {"ip": "79.208.166.201", "source": "test", "since": datetime.utcnow().isoformat()})
    r = client.post("/api/security/blocks", headers=admin, json={"cidr": "79.208.166.201", "hours": 1})
    assert r.status_code == 422 and "eigene" in r.text
    assert client.post("/api/security/blocks", headers=admin, json={"cidr": "79.208.166.0/24", "hours": 1}).status_code == 422
