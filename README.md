# NetworkHelper

Überblick über die Dienste auf deinem Proxmox-Server: wer greift auf welche Adresse zu, wie sicher ist alles von außen, und DNS-Einträge bei Porkbun legen sich von selbst an. Läuft in einem LXC-Container, Design wie beim BikeHelper.

## Was NetworkHelper kann

**Zugriffe sichtbar machen**
- Liest die Zugriffsprotokolle des Nginx Proxy Managers mit (über einen kleinen Agenten) und zeigt Verlauf, Hosts, Herkunftsländer, Netzbetreiber, Antwortcodes, Pfade und ein durchsuchbares Rohprotokoll.
- **Herkunftskarte:** Eine Weltkarte zeigt, woher die Zugriffe kommen. Punktgröße = Anzahl, Farbe = Grund (du und deine Nutzer, nützliche Dienste, automatisches Rauschen, Angriffe). Mit Ausschnitten für Welt, Europa und Deutschland, Zoom und einer Liste der Adressen je Ort.
- **Wer & warum:** NetworkHelper ordnet jede Adresse einer verständlichen Ursache zu, mit Begründung: Heimnetz, du selbst über deine Domain, Apps (Nextcloud, Jellyfin, Home Assistant …), Browser-Besuche, Let's Encrypt, Erreichbarkeits-Prüfer, Suchmaschinen und KI-Crawler, Link-Vorschauen (WhatsApp, Telegram …), Internet-Vermessung (Censys, Shodan …), Rechenzentrums-Bots, Herumstochern, Schwachstellen-Suche und Passwort-Angriffe. Falsche „Googlebots“ aus fremden Rechenzentren werden erkannt.
- Ein Klick auf eine IP zeigt alles zu dieser Adresse: warum sie zugreift, Ziele, Programme, letzte Anfragen, Vorfälle, Sperren.
- Live-Verbindungen: Jeder Server mit Agent meldet alle 30 Sekunden aktive Verbindungen und offene Ports, dazu Last, Speicher und Docker-Container.
- Land und Netzbetreiber kommen offline aus den freien Datenbanken von DB-IP. Keine IP-Adresse verlässt dafür den Server.

**Sicherheitsstatus überwachen**
- Ampel mit Punktzahl auf der Startseite, jeder Abzug begründet.
- Offene Ports: regelmäßiger Scan der öffentlichen IP (rund 100 häufige Ports, anpassbar) plus der Blick von außen über Shodan InternetDB. Riskante Ports wie Proxmox (8006), SSH oder Datenbanken lösen eine kritische Warnung aus. Gewollte Ports markierst du als erwartet.
- Anleitungen zum Schließen: Bei jedem unerwarteten offenen Port zeigt „So schließt du ihn“ Schritt für Schritt den Weg in der FRITZ!Box (Portfreigabe löschen, UPnP, Fernzugriff, TR-069, VPN statt offener Ports). Unter „Router absichern“ gibt es eine Checkliste zum Abhaken. Für andere Router stehen allgemeine Anleitungen bereit (Administration → Allgemein → Dein Router).
- Zertifikate und Sicherheits-Header je Hostname mit Note A bis F, Warnung 14 und 5 Tage vor Ablauf, Hilfe zum Beheben im Proxy Manager.
- Auffällige Zugriffe: Schwachstellen-Suchen (/.env, /wp-login.php …), Angriffswerkzeuge, viele fehlgeschlagene Anmeldungen, Verzeichnis-Scans, ungewöhnlich viele Anfragen.
- Sperrliste: per Klick oder automatisch. Der Agent setzt sie im Proxy Manager als `deny`-Regeln um, gesperrte Adressen bekommen „403“.
- Erreichbarkeit: Statusseite mit Verlauf, Verfügbarkeit über 24 Stunden, 7 und 30 Tage und Antwortzeiten. Für jeden Proxy Host entsteht automatisch ein Monitor.

**DNS automatisch bei Porkbun**
- Records ansehen, anlegen und löschen.
- DynDNS: markierte A-Records folgen automatisch der öffentlichen IP.
- Abgleich mit dem Proxy Manager: zeigt, welche Proxy Hosts noch keinen DNS-Eintrag haben, legt sie per Klick oder auf Wunsch automatisch an (A-Record mit DynDNS oder CNAME auf die Hauptdomain).

**Warnungen per E-Mail**, gesammelt statt einzeln (kritische sofort), mit einstellbarer Schwelle. Alle Meldungen stehen zusätzlich unter „Meldungen“.

## Installation auf Proxmox

### Variante A: Ein Befehl auf dem Proxmox-Host (empfohlen)

In der Proxmox-Oberfläche: Rechenzentrum → dein Knoten → **Shell**, dann:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Tillhnz/NetworkHelper/main/proxmox/create-lxc.sh)"
```

Das Skript legt einen Debian-12-LXC an (2 Kerne, 2 GB RAM, 8 GB Festplatte, `nesting` und `keyctl` für Docker), startet ihn und installiert NetworkHelper unter `/opt/NetworkHelper`. Anpassen lässt sich alles über Variablen, zum Beispiel:

```bash
CTID=130 STORAGE=local-zfs IP=192.168.1.50/24 GW=192.168.1.1 bash -c "$(curl -fsSL https://raw.githubusercontent.com/Tillhnz/NetworkHelper/main/proxmox/create-lxc.sh)"
```

### Variante B: In einem vorhandenen LXC oder einer VM

Debian oder Ubuntu, bei einem LXC mit aktivierten Optionen **nesting** und **keyctl** (Container → Optionen → Features). Dann im Container als root:

```bash
curl -fsSL https://raw.githubusercontent.com/Tillhnz/NetworkHelper/main/install.sh | bash
```

Das Skript installiert bei Bedarf Git und Docker, erzeugt Passwörter, schreibt die `.env` und startet alles. Danach ist NetworkHelper unter `http://<IP-des-Containers>:8080` erreichbar.

## Einführung für Einsteiger

Beim ersten Anmelden führt ein **Einrichtungs-Assistent** Schritt für Schritt durch alles: Agent installieren (mit Live-Anzeige, sobald er sich meldet), Proxy Manager verbinden, Porkbun verbinden und E-Mail einrichten, jeweils mit Test-Knopf. Jeder Schritt lässt sich überspringen.

Danach zeigt eine **geführte Tour** in 15 kurzen Schritten, wo du was findest. Dazu kommen:
- **Erklärkästen** oben auf jeder Seite („Was sehe ich hier?“), mit „Verstanden“ ausblendbar.
- **Anklickbare Fachbegriffe:** Gepunktet unterstrichene Wörter und kleine **?** erklären Port, DNS, DynDNS, Zertifikat und Co. direkt an Ort und Stelle.
- Die Seite **Hilfe** mit Schaubild („So hängt alles zusammen“), Farberklärung, „Was tun, wenn …“ für typische Meldungen und einem Lexikon zum Durchsuchen.

Tour, Assistent und ausgeblendete Erklärungen holst du jederzeit unter Einstellungen → Einführung zurück.

## Einrichten in 4 Schritten

1. **Konto anlegen.** Das erste Konto wird Administrator, danach ist die Registrierung geschlossen (weitere Personen per Einladung).
2. **Agent auf den Proxy Manager.** Unter „Verbindungen“ einen Agenten anlegen und den angezeigten Befehl im LXC mit dem Nginx Proxy Manager als root ausführen. Der Agent findet den Proxy Manager selbst, egal ob er in Docker oder direkt installiert ist (zum Beispiel per Proxmox-Community-Skript). Soll die Sperrliste wirken, den Schalter „Sperrliste umsetzen“ einschalten (fügt `--enforce-blocks` an).
3. **Proxy Manager verbinden** (Administration → Proxy Manager): Adresse der Verwaltung (meist `http://IP:81`), E-Mail und Passwort. Am besten ein eigenes Konto im Proxy Manager anlegen. Dann entstehen Monitore und Zertifikatsprüfungen automatisch.
4. **Porkbun verbinden** (Administration → DNS): Bei Porkbun unter *Account → API Access* einen Schlüssel erzeugen und bei jeder Domain unter *Details* den Schalter **API Access** einschalten. Schlüssel und Secret eintragen, „Verbindung testen“.

Optional: E-Mail unter Administration → E-Mail (Gmail: App-Passwort verwenden) und die Sicherheitsoptionen (Portliste, automatische Sperre).

## Der Agent

Ein einzelnes Python-Skript ohne Abhängigkeiten (`agent/nh-agent.py`, ab Python 3.7), als systemd-Dienst `networkhelper-agent`.

- Liest `proxy-host-*_access.log`, `redirection-host-*_access.log` und `fallback_access.log` im Logordner des Proxy Managers mit. Beim ersten Start liefert er das letzte Stück jeder Datei nach. Rotierte Dateien werden erkannt, nicht gesendete Zeilen gehen bei Verbindungsabbrüchen nicht verloren.
- Meldet aktive Verbindungen und offene Ports (`ss`), Adressen, Last, Speicher und Docker-Container.
- Mit `--enforce-blocks`: schreibt die Sperrliste nach `data/nginx/custom/networkhelper_blocklist.conf`, bindet sie über `server_proxy.conf` in alle Proxy Hosts ein, prüft die Konfiguration mit `nginx -t` und lädt nginx neu. Ist die Konfiguration fehlerhaft, wird die Änderung zurückgenommen.

```bash
journalctl -u networkhelper-agent -f            # Protokoll
systemctl restart networkhelper-agent           # Neustart
curl -fsSL http://NETWORKHELPER:8080/api/agent/files/install.sh | bash -s -- --enforce-blocks   # Option ändern (Server und Token bleiben)
curl -fsSL http://NETWORKHELPER:8080/api/agent/files/install.sh | bash -s -- --uninstall        # Entfernen
```

Den Agenten kannst du auch auf weiteren Servern installieren. Ohne Proxy Manager meldet er nur Verbindungen und Ports.

## Gut zu wissen

- **Portscan aus dem Heimnetz.** Der eigene Scan läuft über die öffentliche Adresse und wird vom Router per NAT-Loopback beantwortet. Er zeigt zuverlässig die Portweiterleitungen, kann aber auch Ports des Routers selbst zeigen, die von außen geschlossen sind. Shodan liefert den echten Außenblick, allerdings nur etwa wöchentlich.
- **Echte Client-IP.** Die Zugriffsprotokolle zeigen die Adresse, die beim Proxy Manager ankommt. Läuft davor noch Cloudflare oder ein anderer Proxy, steht dort dessen Adresse.
- **Externe Dienste**, die NetworkHelper anspricht: Porkbun (DNS, öffentliche IP), download.db-ip.com (einmal im Monat), internetdb.shodan.io (nur die öffentliche IP), api.ipify.org als Ersatz zur IP-Ermittlung, solange Porkbun nicht verbunden ist. GeoIP und Shodan lassen sich abschalten, die öffentliche IP lässt sich fest vorgeben.
- **Speicher.** Zugriffe werden 30 Tage aufbewahrt (einstellbar). Für einen Heimserver sind das meist wenige hundert MB.

## Befehle im Projektordner

| Befehl | Wirkung |
|---|---|
| `./install.sh update` | Neueste Version holen und neu starten |
| `./install.sh url https://network.example.de` | Adresse ändern |
| `./install.sh backup` | Datenbank nach `backups/` sichern |
| `./install.sh restore backups/DATEI` | Sicherung zurückspielen |
| `./install.sh logs` | Protokolle anzeigen |

Updates gehen auch per Knopf unter Administration → Übersicht. Vorher wird die Datenbank gesichert; startet die neue Version nicht, geht NetworkHelper automatisch zurück.

## Aufbau

| Teil | Technik |
|---|---|
| `backend/` | FastAPI, SQLAlchemy, PostgreSQL; Hintergrundaufgaben für Scans, Prüfungen, DynDNS und Mails |
| `frontend/` | React und Vite, ausgeliefert über nginx |
| `agent/` | Agent und sein Installationsskript, werden vom Backend ausgeliefert |
| `updater/` | Update-Dienst für den Knopf in der Administration |
| `proxmox/` | Skript zum Anlegen des LXC |

### Entwicklung

```bash
cd backend && pip install -r requirements-dev.txt
python -m pytest                                  # Tests
BACKGROUND_JOBS=false uvicorn app.main:app --reload   # http://localhost:8000 mit SQLite

cd frontend && npm install && npm run dev         # http://localhost:5173, /api geht ans Backend
```

GitHub Actions prüft bei jedem Push Backend (ruff, pytest), Frontend-Build, Skripte und Compose-Datei.

## Lizenzen und Quellen

IP-Geolokalisierung: [IP Geolocation by DB-IP](https://db-ip.com) (CC BY 4.0). Weltkarte: [Natural Earth](https://www.naturalearthdata.com) (gemeinfrei), erzeugt mit `tools/build_world.py`. Außenansicht: [Shodan InternetDB](https://internetdb.shodan.io). DNS: [Porkbun API v3](https://porkbun.com/api/json/v3/documentation).
