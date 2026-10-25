#!/bin/sh
# Erlaubt das Einbetten von NetworkHelper in bestimmte Seiten (z. B. Home Assistant), wenn FRAME_ANCESTORS gesetzt ist.
# Beispiel: FRAME_ANCESTORS="https://ha.example.de http://192.168.1.20:8123"
set -eu
SNIPPET=/etc/nginx/snippets/security-headers.conf
VALUE="${FRAME_ANCESTORS:-}"
[ -z "$VALUE" ] && exit 0
# Nur Adressen zulassen (Schema, Name, Port, *), keine Zeichen, die die nginx-Konfiguration verändern könnten
if ! printf '%s' "$VALUE" | grep -Eq '^[A-Za-z0-9:/._*+ -]+$'; then
  echo "FRAME_ANCESTORS enthält ungültige Zeichen, Einbetten bleibt verboten" >&2
  exit 0
fi
sed -i '/X-Frame-Options/d' "$SNIPPET"
sed -i "s|frame-ancestors 'none'|frame-ancestors 'self' $VALUE|" "$SNIPPET"
echo "NetworkHelper darf eingebettet werden in: $VALUE"
