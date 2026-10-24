#!/usr/bin/env bash
# Legt auf dem Proxmox-Host einen Debian-12-LXC an und installiert NetworkHelper darin.
#
# Auf dem Proxmox-Host als root (Shell im Web-UI: Rechenzentrum → Knoten → Shell):
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/Tillhnz/NetworkHelper/main/proxmox/create-lxc.sh)"
#
# Anpassen per Umgebungsvariablen (alle optional):
#   CTID=120              Container-ID (Standard: nächste freie)
#   CT_HOSTNAME=networkhelper
#   STORAGE=local-lvm     Speicher für die Festplatte des Containers
#   TEMPLATE_STORAGE=local
#   DISK_GB=8  CORES=2  MEMORY_MB=2048
#   BRIDGE=vmbr0
#   IP=dhcp               oder fest, z. B. IP=192.168.1.50/24 GW=192.168.1.1
#   VLAN=                 VLAN-Tag, falls nötig
set -euo pipefail

info() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✔\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m✘\033[0m %s\n' "$*" >&2; exit 1; }

command -v pct >/dev/null 2>&1 || die "Dieses Skript läuft auf dem Proxmox-Host (pct fehlt)."
[ "$(id -u)" -eq 0 ] || die "Bitte als root ausführen."

CTID="${CTID:-$(pvesh get /cluster/nextid)}"
CT_HOSTNAME="${CT_HOSTNAME:-networkhelper}"
STORAGE="${STORAGE:-local-lvm}"
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-local}"
DISK_GB="${DISK_GB:-8}"
CORES="${CORES:-2}"
MEMORY_MB="${MEMORY_MB:-2048}"
BRIDGE="${BRIDGE:-vmbr0}"
IP="${IP:-dhcp}"
GW="${GW:-}"
VLAN="${VLAN:-}"

pct status "$CTID" >/dev/null 2>&1 && die "Container $CTID existiert bereits. Wähle eine andere ID mit CTID=…"

info "Suche die aktuelle Debian-12-Vorlage …"
pveam update >/dev/null
TEMPLATE="$(pveam available --section system | awk '/debian-12-standard/ {print $2}' | sort -V | tail -n 1)"
[ -n "$TEMPLATE" ] || die "Keine Debian-12-Vorlage gefunden."
if ! pveam list "$TEMPLATE_STORAGE" | grep -q "$TEMPLATE"; then
  info "Lade $TEMPLATE …"
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE" >/dev/null
fi

NET="name=eth0,bridge=$BRIDGE,ip=$IP"
[ -n "$GW" ] && NET="$NET,gw=$GW"
[ -n "$VLAN" ] && NET="$NET,tag=$VLAN"

info "Lege Container $CTID ($CT_HOSTNAME) an …"
# nesting und keyctl braucht Docker im Container
pct create "$CTID" "$TEMPLATE_STORAGE:vztmpl/$TEMPLATE" \
  --hostname "$CT_HOSTNAME" --cores "$CORES" --memory "$MEMORY_MB" --swap 512 \
  --rootfs "$STORAGE:$DISK_GB" --net0 "$NET" \
  --features nesting=1,keyctl=1 --unprivileged 1 --onboot 1 \
  --description "NetworkHelper – https://github.com/Tillhnz/NetworkHelper" >/dev/null
pct start "$CTID"

info "Warte auf das Netzwerk …"
CT_IP=""
for _ in $(seq 1 60); do
  CT_IP="$(pct exec "$CTID" -- sh -c "hostname -I 2>/dev/null | awk '{print \$1}'" || true)"
  if [ -n "$CT_IP" ] && pct exec "$CTID" -- sh -c "getent hosts github.com >/dev/null"; then break; fi
  sleep 2
done
[ -n "$CT_IP" ] || die "Der Container bekommt keine IP-Adresse. Prüfe Bridge und DHCP."
ok "Container läuft unter $CT_IP"

info "Installiere NetworkHelper im Container (dauert einige Minuten) …"
pct exec "$CTID" -- bash -c "apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null"
pct exec "$CTID" -- bash -c "export NETWORKHELPER_PUBLIC_URL=http://$CT_IP:8080 NETWORKHELPER_DIR=/opt/NetworkHelper; curl -fsSL https://raw.githubusercontent.com/Tillhnz/NetworkHelper/main/install.sh | bash"

cat <<EOF

────────────────────────────────────────────────────────
 NetworkHelper läuft im Container $CTID.

 Öffnen:     http://$CT_IP:8080
 Konsole:    pct enter $CTID   (Projektordner /opt/NetworkHelper)

 Tipp: Gib dem Container im Router eine feste IP-Adresse,
 damit die Agenten ihn immer unter derselben Adresse finden.
────────────────────────────────────────────────────────
EOF
