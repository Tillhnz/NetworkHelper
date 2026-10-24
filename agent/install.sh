#!/usr/bin/env bash
# NetworkHelper-Agent installieren, aktualisieren oder entfernen.
#
# Den fertigen Befehl mit Token zeigt NetworkHelper unter „Verbindungen → Agent hinzufügen“. Er sieht so aus:
#   curl -fsSL http://NETWORKHELPER/api/agent/files/install.sh | sudo bash -s -- --server http://NETWORKHELPER --token nh_…
#
# Optionen:
#   --server URL        Adresse von NetworkHelper (Pflicht bei der ersten Installation)
#   --token TOKEN       Token des Agenten (Pflicht bei der ersten Installation)
#   --enforce-blocks    Sperrliste im Nginx Proxy Manager umsetzen (deny-Regeln, nginx wird neu geladen)
#   --no-enforce-blocks Sperrliste nicht umsetzen
#   --logs "GLOB,GLOB"  Eigene Protokolldateien statt der automatisch gefundenen
#   --insecure          Selbst signiertes Zertifikat von NetworkHelper akzeptieren
#   --uninstall         Agent entfernen
set -euo pipefail

DIR=/opt/networkhelper-agent
CONF=/etc/networkhelper-agent.json
UNIT=/etc/systemd/system/networkhelper-agent.service
SERVER="" TOKEN="" ENFORCE="" LOGS="" INSECURE="" UNINSTALL=""

info() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✔\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m✘\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="${2%/}"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --enforce-blocks) ENFORCE=true; shift ;;
    --no-enforce-blocks) ENFORCE=false; shift ;;
    --logs) LOGS="$2"; shift 2 ;;
    --insecure) INSECURE=true; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    *) die "Unbekannte Option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "Bitte als root ausführen (oder mit sudo)."
command -v systemctl >/dev/null 2>&1 || die "systemd fehlt. Der Agent braucht einen Server mit systemd."

if [ -n "$UNINSTALL" ]; then
  systemctl disable --now networkhelper-agent 2>/dev/null || true
  rm -f "$UNIT" "$CONF"
  rm -rf "$DIR" /var/lib/networkhelper-agent
  systemctl daemon-reload
  ok "Agent entfernt. Eine eingebundene Sperrliste im Proxy Manager (server_proxy.conf) bitte von Hand entfernen."
  exit 0
fi

# Bestehende Einstellungen übernehmen (Update ohne Parameter)
if [ -f "$CONF" ] && command -v python3 >/dev/null 2>&1; then
  [ -n "$SERVER" ] || SERVER="$(python3 -c "import json;print(json.load(open('$CONF'))['server'])")"
  [ -n "$TOKEN" ] || TOKEN="$(python3 -c "import json;print(json.load(open('$CONF'))['token'])")"
fi
[ -n "$SERVER" ] && [ -n "$TOKEN" ] || die "Bitte --server und --token angeben (den Befehl zeigt NetworkHelper beim Anlegen des Agenten)."

# ---------- Pakete ----------
missing=()
command -v python3 >/dev/null 2>&1 || missing+=(python3)
command -v ss >/dev/null 2>&1 || missing+=(iproute2)
command -v curl >/dev/null 2>&1 || missing+=(curl)
if [ "${#missing[@]}" -gt 0 ]; then
  command -v apt-get >/dev/null 2>&1 || die "Bitte installiere: ${missing[*]}"
  info "Installiere ${missing[*]} …"
  apt-get update -qq && apt-get install -y -qq "${missing[@]}" >/dev/null
fi

# ---------- Agent laden ----------
info "Lade den Agenten von $SERVER …"
mkdir -p "$DIR"
curl_opts=(-fsSL)
[ "$INSECURE" = true ] && curl_opts+=(-k)
curl "${curl_opts[@]}" "$SERVER/api/agent/files/nh-agent.py" -o "$DIR/nh-agent.py.new" \
  || die "Download fehlgeschlagen. Ist $SERVER von diesem Server aus erreichbar?"
python3 -m py_compile "$DIR/nh-agent.py.new" || die "Die geladene Datei ist kein gültiges Python."
mv "$DIR/nh-agent.py.new" "$DIR/nh-agent.py"
chmod 755 "$DIR/nh-agent.py"

# ---------- Nginx Proxy Manager finden ----------
NPM_DIR="" NPM_CONTAINER=""
if command -v docker >/dev/null 2>&1; then
  for c in $(docker ps --format '{{.Names}}' 2>/dev/null); do
    img="$(docker inspect -f '{{.Config.Image}}' "$c" 2>/dev/null || true)"
    case "$img" in
      *nginx-proxy-manager*)
        NPM_CONTAINER="$c"
        NPM_DIR="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$c" 2>/dev/null || true)"
        break ;;
    esac
  done
fi
if [ -z "$NPM_DIR" ] && [ -d /data/logs ] && [ -d /data/nginx ]; then
  NPM_DIR=/data  # Proxy Manager ohne Docker (zum Beispiel Proxmox-Community-Skript)
fi

if [ -n "$LOGS" ]; then
  GLOBS="$LOGS"
elif [ -n "$NPM_DIR" ]; then
  GLOBS="$NPM_DIR/logs/proxy-host-*_access.log,$NPM_DIR/logs/redirection-host-*_access.log,$NPM_DIR/logs/fallback_access.log"
  ok "Nginx Proxy Manager gefunden: $NPM_DIR${NPM_CONTAINER:+ (Container $NPM_CONTAINER)}"
else
  GLOBS=""
  warn "Kein Nginx Proxy Manager gefunden. Der Agent meldet nur Verbindungen. Protokolle später mit --logs angeben."
fi

if [ -z "$ENFORCE" ]; then
  ENFORCE=false
  if [ -f "$CONF" ]; then
    ENFORCE="$(python3 -c "import json;print(str(json.load(open('$CONF')).get('enforce_blocks', False)).lower())")"
  fi
fi
if [ "$ENFORCE" = true ] && [ -z "$NPM_DIR" ]; then
  warn "Sperrliste kann ohne Proxy Manager nicht umgesetzt werden, schalte sie aus."
  ENFORCE=false
fi

# ---------- Konfiguration ----------
umask 077
SERVER="$SERVER" TOKEN="$TOKEN" GLOBS="$GLOBS" ENFORCE="$ENFORCE" NPM_DIR="$NPM_DIR" NPM_CONTAINER="$NPM_CONTAINER" INSECURE="${INSECURE:-false}" CONF="$CONF" python3 - <<'PY'
import json, os
conf = os.environ["CONF"]
cfg = {}
if os.path.exists(conf):
    try:
        cfg = json.load(open(conf))
    except ValueError:
        cfg = {}
cfg.update({
    "server": os.environ["SERVER"], "token": os.environ["TOKEN"],
    "log_globs": [g.strip() for g in os.environ["GLOBS"].split(",") if g.strip()],
    "enforce_blocks": os.environ["ENFORCE"] == "true",
    "npm_data_dir": os.environ["NPM_DIR"], "npm_container": os.environ["NPM_CONTAINER"],
    "insecure": os.environ["INSECURE"] == "true",
})
with open(conf, "w") as f:
    json.dump(cfg, f, indent=2)
PY
chmod 600 "$CONF"

cat > "$UNIT" <<EOF
[Unit]
Description=NetworkHelper-Agent (Zugriffe und Verbindungen)
After=network-online.target docker.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/env python3 $DIR/nh-agent.py
Restart=always
RestartSec=10
Nice=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable networkhelper-agent >/dev/null 2>&1
systemctl restart networkhelper-agent
sleep 3
if systemctl is-active --quiet networkhelper-agent; then
  ok "Agent läuft. In NetworkHelper sollte er unter „Verbindungen“ gleich als online erscheinen."
else
  warn "Der Agent startet nicht. Details: journalctl -u networkhelper-agent -n 50"
fi
echo
echo "Sperrliste im Proxy Manager: $([ "$ENFORCE" = true ] && echo an || echo aus)  (ändern: Befehl erneut mit --enforce-blocks oder --no-enforce-blocks)"
echo "Protokoll des Agenten:       journalctl -u networkhelper-agent -f"
