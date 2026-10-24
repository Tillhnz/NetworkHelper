#!/usr/bin/env bash
# NetworkHelper – Installations- und Hilfsskript
#
# Installieren (auf einer frischen Debian-/Ubuntu-Maschine):
#   curl -fsSL https://raw.githubusercontent.com/Tillhnz/NetworkHelper/main/install.sh | bash
#   oder im geklonten Projektordner: ./install.sh
#
# Weitere Befehle:
#   ./install.sh update          Neueste Version holen und neu starten
#   ./install.sh lock            Neue Registrierungen sperren
#   ./install.sh unlock          Neue Registrierungen wieder erlauben
#   ./install.sh url <adresse>   Öffentliche Adresse ändern (z. B. https://network.example.de)
#   ./install.sh backup          Datenbank in den Ordner backups/ sichern
#   ./install.sh restore <datei> Eine Sicherung zurückspielen (ersetzt alle aktuellen Daten)
#   ./install.sh logs            Protokolle anzeigen
#
# Umgebungsvariablen (optional):
#   NETWORKHELPER_DIR=<ordner>        Zielordner bei der Installation (Standard: ~/NetworkHelper)
#   NETWORKHELPER_PUBLIC_URL=<url>    Öffentliche Adresse ohne Rückfrage setzen
#   NETWORKHELPER_REPO=<git-url>      Anderes Repository verwenden
set -euo pipefail

REPO_URL="${NETWORKHELPER_REPO:-https://github.com/Tillhnz/NetworkHelper.git}"
DEFAULT_DIR="${NETWORKHELPER_DIR:-$HOME/NetworkHelper}"

info() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✔\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m✘\033[0m %s\n' "$*" >&2; exit 1; }

# ---------- Hilfsfunktionen ----------

as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    die "Dafür sind Root-Rechte nötig. Melde dich als root an oder installiere sudo (apt install sudo)."
  fi
}

random_hex() { # $1 = Anzahl Bytes
  head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'
}

ask() { # $1 = Frage, $2 = Standardwert; funktioniert auch bei "curl | bash"
  local answer=""
  if [ -t 0 ]; then
    read -r -p "$1 [$2]: " answer || answer=""
  elif (exec </dev/tty) 2>/dev/null; then
    read -r -p "$1 [$2]: " answer </dev/tty || answer=""
  fi
  printf '%s' "${answer:-$2}"
}

# Ordner bestimmen: neben diesem Skript, falls dort das Projekt liegt, sonst Standardordner
script_dir=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
if [ -n "$script_dir" ] && [ -f "$script_dir/docker-compose.yml" ]; then
  APP_DIR="$script_dir"
else
  APP_DIR="$DEFAULT_DIR"
fi

get_env() { # KEY
  [ -f "$APP_DIR/.env" ] || return 0
  grep -E "^$1=" "$APP_DIR/.env" | head -n 1 | cut -d= -f2- || true
}

set_env() { # KEY VALUE
  local key="$1" raw="$2" file="$APP_DIR/.env" value
  value="${raw//\\/\\\\}"
  value="${value//&/\\&}"
  value="${value//|/\\|}"
  if grep -q "^${key}=" "$file"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    printf '%s=%s\n' "$key" "$raw" >> "$file"
  fi
}

web_port() { local p; p="$(get_env WEB_PORT)"; printf '%s' "${p:-8080}"; }

local_ip() {
  local ip=""
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')" || ip=""
  printf '%s' "${ip:-localhost}"
}

# ---------- Schritte ----------

ensure_packages() {
  local missing=()
  command -v git >/dev/null 2>&1 || missing+=(git)
  command -v curl >/dev/null 2>&1 || missing+=(curl)
  if [ "${#missing[@]}" -gt 0 ]; then
    command -v apt-get >/dev/null 2>&1 || die "Bitte installiere ${missing[*]} und starte das Skript erneut."
    info "Installiere ${missing[*]} …"
    as_root apt-get update -qq
    as_root apt-get install -y -qq "${missing[@]}"
  fi
}

ensure_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    info "Installiere Docker (offizielles Skript von get.docker.com) …"
    local tmp; tmp="$(mktemp)"
    curl -fsSL https://get.docker.com -o "$tmp"
    as_root sh "$tmp"
    rm -f "$tmp"
    if [ "$(id -u)" -ne 0 ]; then
      as_root usermod -aG docker "${USER:-$(id -un)}" || true
    fi
  fi
  pick_docker
  "${DOCKER[@]}" compose version >/dev/null 2>&1 \
    || die "Docker Compose fehlt. Bitte installiere das Docker-Compose-Plugin (siehe docs.docker.com/compose/install)."
  ok "Docker ist bereit."
}

# Mit oder ohne Root-Rechte, je nachdem, ob der Benutzer schon in der docker-Gruppe ist
pick_docker() {
  if docker info >/dev/null 2>&1; then
    DOCKER=(docker)
  elif as_root docker info >/dev/null 2>&1; then
    DOCKER=(as_root docker)
  else
    die "Der Docker-Dienst antwortet nicht. Prüfe mit: sudo systemctl status docker"
  fi
}

ensure_repo() {
  if [ -f "$APP_DIR/docker-compose.yml" ]; then
    return
  fi
  info "Lade NetworkHelper nach $APP_DIR …"
  git clone --depth 1 "$REPO_URL" "$APP_DIR"
}

setup_env() {
  local env="$APP_DIR/.env"
  if [ -f "$env" ]; then
    ok ".env existiert bereits und bleibt unverändert."
    return
  fi
  cp "$APP_DIR/.env.example" "$env"
  chmod 600 "$env"
  set_env POSTGRES_PASSWORD "$(random_hex 16)"
  set_env SECRET_KEY "$(random_hex 32)"

  local url="${NETWORKHELPER_PUBLIC_URL:-}"
  if [ -z "$url" ]; then
    echo
    echo "Unter welcher Adresse wird NetworkHelper später erreichbar sein?"
    echo "Noch keine Domain? Dann einfach Enter drücken, das lässt sich später ändern."
    url="$(ask "Adresse" "http://$(local_ip):$(web_port)")"
  fi
  url="${url%/}"
  set_env PUBLIC_URL "$url"
  ok ".env mit zufälligen Passwörtern angelegt."
}

start_stack() {
  info "Baue und starte NetworkHelper (der erste Start dauert einige Minuten) …"
  (cd "$APP_DIR" && "${DOCKER[@]}" compose up -d --build)
}

wait_healthy() {
  local port; port="$(web_port)"
  info "Warte, bis NetworkHelper antwortet …"
  for _ in $(seq 1 60); do
    if curl -fsS "http://localhost:${port}/api/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

report_start() {
  if wait_healthy; then
    ok "NetworkHelper läuft."
  else
    warn "NetworkHelper antwortet noch nicht. Die letzten Protokollzeilen:"
    (cd "$APP_DIR" && "${DOCKER[@]}" compose logs --tail 40) || true
    die "Start nicht bestätigt. Mehr Details mit: ./install.sh logs"
  fi
}

# ---------- Befehle ----------

cmd_install() {
  ensure_packages
  ensure_docker
  ensure_repo
  setup_env
  start_stack
  report_start

  local port ip; port="$(web_port)"; ip="$(local_ip)"
  cat <<EOF

────────────────────────────────────────────────────────
 NetworkHelper ist installiert.

 Öffnen:        http://${ip}:${port}
 Ordner:        ${APP_DIR}

 Nächste Schritte
 1. Öffne die Adresse oben und lege dein Konto an (das erste Konto
    wird Administrator, danach ist die Registrierung geschlossen).
 2. Unter „Verbindungen“ einen Agenten anlegen und den angezeigten
    Befehl im LXC mit dem Nginx Proxy Manager ausführen.
 3. Unter „Administration“ Porkbun, Proxy Manager und E-Mail eintragen.
 4. Wenn NetworkHelper über den Proxy Manager erreichbar sein soll:
      ./install.sh url https://deine-domain.de

 Aktualisieren:  ./install.sh update
────────────────────────────────────────────────────────
EOF
}

require_install() {
  [ -f "$APP_DIR/docker-compose.yml" ] && [ -f "$APP_DIR/.env" ] \
    || die "Keine Installation in $APP_DIR gefunden. Starte zuerst: ./install.sh"
  command -v docker >/dev/null 2>&1 || die "Docker ist nicht installiert."
  pick_docker
}

cmd_update() {
  require_install
  if [ -d "$APP_DIR/.git" ]; then
    info "Hole die neueste Version …"
    git -C "$APP_DIR" pull --ff-only
  else
    warn "Kein Git-Ordner, überspringe das Herunterladen."
  fi
  start_stack
  report_start
  ok "Update abgeschlossen."
}

cmd_registration() { # true|false
  require_install
  set_env ALLOW_REGISTRATION "$1"
  (cd "$APP_DIR" && "${DOCKER[@]}" compose up -d)
  if [ "$1" = "false" ]; then ok "Neue Registrierungen sind gesperrt."; else ok "Neue Registrierungen sind erlaubt."; fi
}

cmd_url() {
  [ -n "${1:-}" ] || die "Bitte eine Adresse angeben, z. B.: ./install.sh url https://network.example.de"
  case "$1" in http://*|https://*) ;; *) die "Die Adresse muss mit http:// oder https:// beginnen." ;; esac
  require_install
  set_env PUBLIC_URL "${1%/}"
  (cd "$APP_DIR" && "${DOCKER[@]}" compose up -d)
  ok "Öffentliche Adresse gesetzt: ${1%/}"
}

cmd_logs() {
  require_install
  (cd "$APP_DIR" && "${DOCKER[@]}" compose logs --tail 100 -f)
}

cmd_backup() {
  require_install
  mkdir -p "$APP_DIR/backups"
  local f="$APP_DIR/backups/networkhelper-$(date +%Y%m%d-%H%M%S).sql.gz"
  (cd "$APP_DIR" && "${DOCKER[@]}" compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' | gzip > "$f")
  chmod 600 "$f"
  [ "$(stat -c %s "$f")" -gt 200 ] || { rm -f "$f"; die "Die Sicherung ist leer, bitte Protokolle prüfen."; }
  ok "Gesichert: $f"
}

cmd_restore() {
  [ -n "${1:-}" ] && [ -f "$1" ] || die "Bitte eine Sicherungsdatei angeben, z. B.: ./install.sh restore backups/networkhelper-20261024-120000.sql.gz"
  require_install
  local file; file="$(readlink -f "$1")"
  warn "Das ersetzt ALLE aktuellen Daten durch den Stand der Sicherung."
  read -r -p "Zum Fortfahren „ja“ eingeben: " answer </dev/tty
  [ "$answer" = "ja" ] || die "Abgebrochen."
  (cd "$APP_DIR" && "${DOCKER[@]}" compose stop backend)
  (cd "$APP_DIR" && "${DOCKER[@]}" compose exec -T db sh -c 'psql -U "$POSTGRES_USER" -d postgres -c "DROP DATABASE IF EXISTS \"$POSTGRES_DB\"" -c "CREATE DATABASE \"$POSTGRES_DB\""')
  gunzip -c "$file" | (cd "$APP_DIR" && "${DOCKER[@]}" compose exec -T db sh -c 'psql -q -U "$POSTGRES_USER" "$POSTGRES_DB"')
  (cd "$APP_DIR" && "${DOCKER[@]}" compose start backend)
  ok "Sicherung zurückgespielt."
}

case "${1:-install}" in
  install)  cmd_install ;;
  update)   cmd_update ;;
  lock)     cmd_registration false ;;
  unlock)   cmd_registration true ;;
  url)      cmd_url "${2:-}" ;;
  backup)   cmd_backup ;;
  restore)  cmd_restore "${2:-}" ;;
  logs)     cmd_logs ;;
  -h|--help|help) sed -n '2,23p' "${BASH_SOURCE[0]:-$0}" | sed 's/^# \{0,1\}//' ;;
  *) die "Unbekannter Befehl: $1 (erlaubt: install, update, lock, unlock, url, backup, restore, logs)" ;;
esac
