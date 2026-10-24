"""Erzeugt die NetworkHelper-Konfiguration für Länder- und Listen-Sperren mit Beispieldaten und eine minimale
nginx.conf drumherum, damit die CI sie mit `nginx -t` prüfen kann:

    python tools/nginx_selftest.py /tmp/nhconf
    docker run --rm -v /tmp/nhconf:/t:ro nginx:1.27-alpine nginx -t -c /t/nginx.conf
"""
import os
import sys
import tempfile

out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/nhconf"
os.makedirs(out, exist_ok=True)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{tempfile.mkdtemp()}/t.db")
os.environ["GEOIP_ENABLED"] = "false"
os.environ["BACKGROUND_JOBS"] = "false"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app import geoblock, state  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.models import GeoRule  # noqa: E402

Base.metadata.create_all(engine)
geoblock.country_networks = lambda cc: {"DE": ["5.0.0.0/16", "2a02:8100::/27"], "AT": ["77.116.0.0/14"]}
geoblock.settings.feed_spamhaus = True
with SessionLocal() as db:
    db.add_all([GeoRule(host="cloud.example.de", countries="DE,AT"), GeoRule(host="*", countries="DE,AT,CH")])
    state.put(db, "feed:spamhaus", {"nets": ["1.10.16.0/20", "2001:db8:1::/48", "10.0.0.0/8", "192.168.0.0/16"]})
    db.commit()
    text = geoblock.http_conf(db)
    _, snippet = geoblock.current(db)
assert "10.0.0.0/8 1;" not in text and "1.10.16.0/20 1;" in text
with open(os.path.join(out, "http.conf"), "w") as f:
    f.write(text)
with open(os.path.join(out, "server.conf"), "w") as f:
    f.write("deny 203.0.113.9;\n" + snippet)
with open(os.path.join(out, "nginx.conf"), "w") as f:
    f.write("events {}\nhttp {\n    include /t/http.conf;\n    server {\n        listen 8080;\n        server_name cloud.example.de;\n"
            "        include /t/server.conf;\n        location / { return 200 ok; }\n    }\n}\n")
print(text)
print(snippet)
