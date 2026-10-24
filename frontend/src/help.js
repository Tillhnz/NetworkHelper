// Alle Erklärtexte an einem Ort: Lexikon, Seiten-Einführungen und die geführte Tour.
// Geschrieben für Menschen, die sich nicht mit Netzwerktechnik auskennen.

export const GLOSSARY = {
  ip: {
    title: "IP-Adresse",
    text: "Die Hausnummer eines Geräts im Netz, zum Beispiel 84.130.20.50. Wer deine Dienste aufruft, hinterlässt seine IP-Adresse im Protokoll.",
  },
  public_ip: {
    title: "Öffentliche IP",
    text: "Die Adresse, unter der dein Anschluss zu Hause im Internet erreichbar ist. Sie gehört deinem Router und wird von deinem Anbieter vergeben. Bei vielen Anschlüssen ändert sie sich gelegentlich, deshalb gibt es DynDNS.",
  },
  private_ip: {
    title: "Heimnetz-Adresse",
    text: "Adressen wie 192.168.x.x oder 10.x.x.x gibt es nur in deinem Heimnetz. Zugriffe von dort kommen von deinen eigenen Geräten und sind unbedenklich.",
  },
  port: {
    title: "Port",
    text: "Wenn die IP-Adresse die Hausnummer ist, dann ist der Port die Wohnungstür. Ein Server kann viele Dienste anbieten, jeder hört an einer eigenen Tür: Webseiten an 80 und 443, SSH an 22, Proxmox an 8006.",
  },
  port_forward: {
    title: "Portweiterleitung",
    text: "Eine Regel im Router, die Anfragen aus dem Internet an einem bestimmten Port zu einem Gerät im Heimnetz durchreicht. Für deine Webdienste brauchst du normalerweise nur 80 und 443, und zwar zum Proxy Manager. Jede weitere offene Tür ist eine mögliche Angriffsfläche.",
  },
  open_port: {
    title: "Offener Port",
    text: "Ein Port, an dem von außen jemand antwortet. Gewollt sind meist nur 80 (HTTP) und 443 (HTTPS). Ein offener Port für Proxmox, SSH oder eine Datenbank lädt Angreifer ein, dort Passwörter auszuprobieren.",
  },
  proxy: {
    title: "Nginx Proxy Manager",
    text: "Der Pförtner deines Servers. Alle Anfragen aus dem Internet kommen bei ihm an. Er schaut auf den Namen (zum Beispiel cloud.deine-domain.de) und leitet weiter an den richtigen Dienst. Er kümmert sich auch um die Zertifikate für HTTPS.",
  },
  proxy_host: {
    title: "Proxy Host",
    text: "Ein Eintrag im Proxy Manager: „Anfragen an cloud.deine-domain.de gehen an 192.168.1.20 Port 80“. Für jeden Dienst, den du von außen erreichen willst, gibt es einen.",
  },
  domain: {
    title: "Domain und Subdomain",
    text: "Der Name deiner Webadresse, zum Beispiel deine-domain.de. Subdomains sind Namen davor, etwa cloud.deine-domain.de oder jellyfin.deine-domain.de. So bekommt jeder Dienst eine eigene Adresse.",
  },
  dns: {
    title: "DNS",
    text: "Das Telefonbuch des Internets. Es übersetzt Namen wie cloud.deine-domain.de in IP-Adressen. Damit deine Dienste erreichbar sind, muss für jeden Namen ein Eintrag (Record) bei deinem Domain-Anbieter stehen.",
  },
  record: {
    title: "DNS-Record",
    text: "Ein Eintrag im Telefonbuch. Die wichtigsten: A-Record (Name zeigt auf eine IPv4-Adresse), AAAA (auf eine IPv6-Adresse), CNAME (Name zeigt auf einen anderen Namen), MX (wohin E-Mails gehen), TXT (Text, zum Beispiel für E-Mail-Echtheit).",
  },
  a_record: {
    title: "A-Record",
    text: "„Dieser Name gehört zu dieser IP-Adresse.“ Für deine Dienste zeigt er auf deine öffentliche IP.",
  },
  cname: {
    title: "CNAME",
    text: "Ein Verweis: „cloud.deine-domain.de ist dasselbe wie deine-domain.de.“ Praktisch, weil sich bei einer neuen IP nur der Haupteintrag ändern muss.",
  },
  ttl: {
    title: "TTL",
    text: "Wie lange sich Geräte einen DNS-Eintrag merken, bevor sie neu nachfragen. 10 Minuten ist für ein Zuhause mit wechselnder IP eine gute Wahl.",
  },
  dyndns: {
    title: "DynDNS",
    text: "Ändert sich deine öffentliche IP, würden deine Namen ins Leere zeigen. DynDNS bemerkt die neue Adresse und trägt sie automatisch bei Porkbun ein. Du musst nichts tun.",
  },
  porkbun: {
    title: "Porkbun",
    text: "Der Anbieter, bei dem deine Domain registriert ist. Über seinen API-Schlüssel darf NetworkHelper deine DNS-Einträge lesen und ändern.",
  },
  api_key: {
    title: "API-Schlüssel",
    text: "Ein Passwort für Programme. Damit darf NetworkHelper in deinem Namen bei Porkbun oder dem Proxy Manager etwas abfragen oder ändern. Er wird nur auf deinem Server gespeichert und nie wieder angezeigt.",
  },
  https: {
    title: "HTTPS und Zertifikat",
    text: "HTTPS verschlüsselt die Verbindung zwischen Browser und deinem Dienst, erkennbar am Schloss in der Adresszeile. Dafür braucht jeder Name ein Zertifikat. Der Proxy Manager holt es kostenlos bei Let's Encrypt und erneuert es alle paar Wochen. Läuft es ab, warnt der Browser alle Besucher.",
  },
  tls: {
    title: "TLS-Version",
    text: "Die Version der Verschlüsselung. TLS 1.2 und 1.3 sind sicher, ältere Versionen nicht mehr.",
  },
  headers: {
    title: "Sicherheits-Header",
    text: "Kleine Zusatzanweisungen, die dein Server an den Browser schickt, etwa „nur verschlüsselt verbinden“ (HSTS) oder „nicht in fremde Seiten einbetten“. Sie schützen Besucher vor einigen Tricks. Fehlen sie, ist das kein Notfall, aber leicht nachzurüsten.",
  },
  hsts: {
    title: "HSTS",
    text: "Sagt dem Browser: „Diese Seite immer nur verschlüsselt öffnen.“ Im Proxy Manager einschaltbar unter SSL → HSTS Enabled.",
  },
  grade: {
    title: "Note A bis F",
    text: "Fasst Zertifikat, Verschlüsselung, Weiterleitung auf HTTPS und Sicherheits-Header zusammen. A und B sind gut, C und schlechter lohnt einen Blick in die Details.",
  },
  status_code: {
    title: "Antwortcode",
    text: "Jede Anfrage bekommt eine dreistellige Antwort. 2xx: hat geklappt. 3xx: weitergeleitet. 4xx: Fehler auf Seite des Besuchers, etwa 401/403 (keine Berechtigung, oft ein falsches Passwort) oder 404 (gibt es nicht). 5xx: Fehler beim Dienst selbst, etwa 502 (Dienst antwortet nicht).",
  },
  user_agent: {
    title: "Programm (User-Agent)",
    text: "Womit jemand zugreift, zum Beispiel ein Browser, die Nextcloud-App oder ein Skript. Angriffswerkzeuge verraten sich hier oft selbst.",
  },
  attack_hit: {
    title: "Ist ein Angriff gelungen?",
    text: "Angreifer probieren bei jedem Server Adressen wie /.env oder /.git/config aus, weil dort oft Passwörter liegen. Bekommen sie „200 OK“, kann das ein Treffer sein, oder die App zeigt einfach ihre Startseite. NetworkHelper ruft diese Adressen deshalb selbst auf und prüft, ob wirklich eine solche Datei ausgeliefert wird. Nur dann gilt der Angriff als gelungen.",
  },
  geo_map: {
    title: "Die Herkunftskarte",
    text: "Jeder Punkt ist ein Ort, von dem aus deine Seiten aufgerufen wurden. Je größer, desto mehr Zugriffe. Die Farbe zeigt, warum: Türkis bist du oder deine Nutzer, Blau sind nützliche Dienste wie Let's Encrypt oder Suchmaschinen, Lila sind automatische Abfragen aus dem Internet und Rot sind Angriffsversuche. Die Linien führen zu deinem Server. Der Standort einer IP-Adresse ist nur eine Schätzung.",
  },
  why_category: {
    title: "Wer & warum",
    text: "NetworkHelper versucht für jede Adresse zu erklären, warum sie zugreift. Dazu schaut er auf den Programmnamen (User-Agent), den Netzbetreiber, die aufgerufenen Seiten und erkannte Vorfälle. Viele Zugriffe auf einen Server im Internet sind ganz normal: Suchmaschinen, Link-Vorschauen oder Firmen, die das Internet vermessen.",
  },
  asn: {
    title: "Netzbetreiber",
    text: "Zu welchem Anbieter eine IP gehört, etwa Deutsche Telekom (ein normaler Internetanschluss) oder ein Rechenzentrum. Zugriffe aus Rechenzentren sind häufiger automatisiert.",
  },
  agent: {
    title: "Agent",
    text: "Ein kleines Programm, das auf einem deiner Server läuft. Es liest die Zugriffsprotokolle des Proxy Managers mit und meldet sie an NetworkHelper, dazu die aktuellen Verbindungen. Ohne Agent sieht NetworkHelper keine Zugriffe.",
  },
  lxc: {
    title: "LXC-Container",
    text: "Ein leichtgewichtiger, abgetrennter Bereich auf deinem Proxmox-Server, wie ein kleiner eigener Rechner. NetworkHelper und dein Proxy Manager laufen jeweils in einem.",
  },
  connection: {
    title: "Aktive Verbindung",
    text: "Ein Gerät, das gerade in diesem Moment mit deinem Server spricht. Von außen sind das meist Leute, die eine deiner Seiten offen haben.",
  },
  incident: {
    title: "Vorfall",
    text: "Ein Muster, das nach Angriff aussieht: jemand sucht nach bekannten Schwachstellen, probiert Passwörter oder fragt hunderte Seiten ab. Im Internet passiert das ständig und automatisch. Ein Vorfall heißt nicht, dass jemand drin ist.",
  },
  bruteforce: {
    title: "Anmeldeversuche (Brute-Force)",
    text: "Jemand probiert in kurzer Zeit viele Passwörter aus. Starke Passwörter und eine Sperre der Adresse helfen.",
  },
  scanner: {
    title: "Schwachstellen-Suche",
    text: "Automatische Programme klopfen an typische Stellen wie /wp-login.php oder /.env, um verwundbare Seiten zu finden. Bei dir gibt es diese Seiten meist gar nicht, dann laufen sie ins Leere (404).",
  },
  blocklist: {
    title: "Sperrliste",
    text: "Adressen auf dieser Liste weist der Proxy Manager ab, sie bekommen nur noch „403 Verboten“. Das setzt der Agent um, wenn du es bei der Installation erlaubt hast.",
  },
  shodan: {
    title: "Shodan",
    text: "Eine Suchmaschine, die das ganze Internet nach offenen Ports absucht. Was Shodan bei dir sieht, sehen auch Angreifer.",
  },
  nat_loopback: {
    title: "NAT-Loopback",
    text: "Fragt ein Gerät aus deinem Heimnetz deine eigene öffentliche Adresse ab, beantwortet das der Router intern. Darum kann der eigene Scan gelegentlich Ports zeigen, die nur von innen offen sind.",
  },
  uptime: {
    title: "Erreichbarkeit",
    text: "Wie viel Prozent der Zeit ein Dienst geantwortet hat. 99,9 % in 30 Tagen heißt: rund 43 Minuten nicht erreichbar.",
  },
  latency: {
    title: "Antwortzeit",
    text: "Wie lange ein Dienst für eine Antwort braucht, in Millisekunden (ms). Unter 300 ms fühlt sich flott an.",
  },
  score: {
    title: "Sicherheitsstatus",
    text: "Startet bei 100 Punkten. Für jedes gefundene Problem gibt es Abzug, die Liste daneben sagt warum. Ab 80 ist alles im grünen Bereich, unter 50 solltest du handeln.",
  },
};

/** Kurze Einführung oben auf jeder Seite. */
export const INTROS = {
  overview: {
    title: "Deine Startseite",
    text: "Hier siehst du auf einen Blick, ob alles in Ordnung ist. Oben links die Ampel für die Sicherheit, rechts daneben deine Dienste. Darunter, wie viel auf deinen Seiten los war und ob etwas Verdächtiges passiert ist. Alles ist anklickbar und führt zu den Details.",
  },
  access: {
    title: "Wer ruft deine Seiten auf?",
    text: "Jeder Aufruf einer deiner Seiten landet hier: wann, welche Seite, von welcher Adresse und mit welchem Ergebnis. Grüne Balken sind normale Aufrufe, gelbe und rote sind Fehler. Unter „Karte“ siehst du, woher die Zugriffe kommen, unter „Wer & warum“, wer sie verursacht. Klick auf eine IP-Adresse, um alles über diesen Besucher zu sehen und ihn bei Bedarf zu sperren.",
  },
  connections: {
    title: "Deine Server und ihre Verbindungen",
    text: "Jeder Server mit einem Agenten erscheint hier als Karte. Du siehst, wer gerade verbunden ist und welche Ports der Server anbietet. Der wichtigste Agent läuft auf dem Container mit dem Nginx Proxy Manager, denn nur er liefert die Zugriffe.",
  },
  security: {
    title: "Wie gut bist du geschützt?",
    text: "Welche Türen (Ports) von außen offen sind und wie du sie in der FRITZ!Box schließt, eine Checkliste zum Absichern deines Routers, ob deine Zertifikate gültig und gut eingerichtet sind, welche verdächtigen Zugriffe es gab, ob ein Angriff tatsächlich etwas erbeuten konnte und welche Adressen gesperrt sind. Rot heißt: bitte ansehen. Gelb heißt: verbesserbar.",
  },
  uptime: {
    title: "Sind deine Dienste erreichbar?",
    text: "NetworkHelper ruft jede Minute alle deine Dienste auf, so wie ein Besucher. Jedes Kästchen steht für eine halbe Stunde: grün lief alles, gelb gab es kurze Aussetzer, rot war der Dienst weg. Fällt etwas aus, bekommst du eine Mail.",
  },
  dns: {
    title: "Die Namen deiner Dienste",
    text: "Damit cloud.deine-domain.de bei dir zu Hause ankommt, braucht jeder Name einen Eintrag bei Porkbun. Hier siehst und änderst du diese Einträge. Unten zeigt der Abgleich, welche Dienste aus dem Proxy Manager noch keinen Eintrag haben.",
  },
  alerts: {
    title: "Alle Meldungen",
    text: "Alles, worauf NetworkHelper dich hingewiesen hat, chronologisch. Kritische Meldungen gehen sofort per Mail raus, andere gesammelt.",
  },
};

/**
 * Geführte Tour. target ist ein data-tour-Wert; fehlt das Element (zum Beispiel ohne Daten), erscheint die Karte mittig.
 * admin: nur für Administratoren.
 */
export const TOUR = [
  { path: "/", target: null, title: "Willkommen bei NetworkHelper", text: "In zwei Minuten zeige ich dir, wo du was findest. Du kannst die Tour jederzeit beenden und später unter „Hilfe“ wieder starten." },
  { path: "/", target: "nav", title: "Das Menü", text: "Sechs Bereiche: Übersicht, Zugriffe (wer ruft deine Seiten auf), Verbindungen (deine Server), Sicherheit, Erreichbarkeit (laufen deine Dienste) und DNS (die Namen deiner Dienste)." },
  { path: "/", target: "score", title: "Die Sicherheits-Ampel", text: "Eine Zahl von 0 bis 100. Für jedes Problem gibt es Abzug, und daneben steht genau, welches. Ein Klick auf einen Punkt führt dich direkt dorthin, wo du es beheben kannst." },
  { path: "/", target: "services", title: "Deine Dienste", text: "Jeder Punkt ist ein Dienst, zum Beispiel Nextcloud oder Jellyfin. Grün: erreichbar. Rot: gerade ausgefallen." },
  { path: "/", target: "kpis", title: "Die wichtigsten Zahlen", text: "Wie viele Aufrufe es in 24 Stunden gab, von wie vielen Adressen, ob es verdächtige Vorfälle gab und wann das nächste Zertifikat abläuft. Gelbe Zahlen verdienen einen Blick." },
  { path: "/access", target: "access-views", title: "Drei Blickwinkel", text: "„Übersicht“ zeigt Zahlen und das Protokoll. „Karte“ zeigt, woher auf der Welt die Zugriffe kommen. „Wer & warum“ erklärt, wer hinter den Zugriffen steckt: du selbst, Suchmaschinen, Scanner oder Angreifer." },
  { path: "/access", target: "access-filters", title: "Zugriffe filtern", text: "Wähle oben den Zeitraum. Mit den Filtern siehst du zum Beispiel nur einen Dienst, nur Fehler oder nur Zugriffe von außen (ohne deine eigenen Geräte)." },
  { path: "/access", target: "access-chart", title: "Der Verlauf", text: "Jeder Balken ist ein Zeitabschnitt. Grün sind erfolgreiche Aufrufe, Gelb Fehler wie „Seite nicht gefunden“ oder „falsches Passwort“, Rot Fehler beim Dienst." },
  { path: "/access", target: "access-ips", title: "Wer besucht dich?", text: "Die häufigsten Adressen mit Land und Anbieter. Klick auf eine IP: Du siehst alles über diesen Besucher und kannst ihn mit einem Klick sperren." },
  { path: "/connections", target: "agents", title: "Deine Server", text: "Hier legst du Agenten an. Der Agent auf dem Proxy-Manager-Container liefert die Zugriffe. Weitere Server kannst du genauso hinzufügen, dann siehst du auch deren Verbindungen." },
  { path: "/security", target: "security-tabs", title: "Sicherheit in vier Bereichen", text: "Offene Ports, eine Checkliste für deinen Router, Zertifikate, verdächtige Vorfälle und die Sperrliste. Bei jedem unerwarteten offenen Port zeigt „So schließt du ihn“ Schritt für Schritt, was du in der FRITZ!Box klicken musst. Gewollte Ports (meist 80 und 443) markierst du als „erwartet“." },
  { path: "/uptime", target: "uptime-list", title: "Erreichbarkeit", text: "Für jeden Dienst die letzten 24 Stunden als Leiste. Fährst du mit der Maus über ein Kästchen, siehst du Uhrzeit und Antwortzeit." },
  { path: "/dns", target: "dns-hero", title: "Deine öffentliche IP und DynDNS", text: "Ändert dein Anbieter die IP deines Anschlusses, trägt NetworkHelper die neue Adresse bei Porkbun ein, damit deine Namen weiter funktionieren." },
  { path: "/dns", target: "dns-records", title: "Neue Namen anlegen", text: "Subdomain eintippen, Schalter „Öffentliche IP“ an, Anlegen. Fertig. Noch einfacher: Unten im Abgleich legt ein Klick die Einträge für alle Dienste aus dem Proxy Manager an." },
  { path: "/", target: "alerts-link", title: "Meldungen", text: "Alles, worauf NetworkHelper dich hingewiesen hat. Wichtiges kommt zusätzlich per Mail." },
  { path: "/", target: "help-link", title: "Hilfe jederzeit", text: "Unter „Hilfe“ findest du ein Lexikon aller Begriffe, ein Schaubild, wie alles zusammenhängt, und Tipps für typische Meldungen. Unterstrichene Begriffe kannst du überall anklicken." },
];

/** Typische Situationen mit konkreten Schritten. */
export const FAQ = [
  {
    q: "Ein Dienst ist „nicht erreichbar“",
    a: [
      "Öffne die Adresse selbst im Browser. Geht sie nicht, liegt es am Dienst, nicht an NetworkHelper.",
      "In Proxmox nachsehen, ob der Container oder die VM des Dienstes läuft.",
      "Antwort 502 heißt: Der Proxy Manager erreicht den Dienst nicht. Prüfe im Proxy Host, ob IP und Port des Dienstes noch stimmen.",
      "Antwort 401 oder 403 ist normal für Seiten mit Anmeldung. Trag beim Monitor unter „Erwartete Antwort“ zum Beispiel 200-499 ein.",
    ],
  },
  {
    q: "Port 8006 (Proxmox) oder 22 (SSH) ist offen",
    a: [
      "Unter Sicherheit → Offene Ports beim Port auf „So schließt du ihn“ klicken. Dort steht Schritt für Schritt, wo du in der FRITZ!Box klicken musst.",
      "Kurz gesagt: in der FRITZ!Box unter Internet → Freigaben → Portfreigaben die Freigabe für diesen Port löschen.",
      "Für den Zugriff von unterwegs besser das VPN der FRITZ!Box (WireGuard) nutzen. Die Anleitung steht unter Sicherheit → Router absichern.",
      "Ist die Freigabe wirklich gewollt, markiere den Port als „erwartet“.",
    ],
  },
  {
    q: "Wie sichere ich meine FRITZ!Box ab?",
    a: [
      "Unter Sicherheit → Router absichern findest du eine Checkliste mit acht Punkten zum Abhaken.",
      "Die wichtigsten: FRITZ!OS aktuell halten, nur die Portfreigaben 80 und 443 zum Proxy Manager behalten und selbstständige Portfreigaben (UPnP) verbieten.",
    ],
  },
  {
    q: "Ein Zertifikat läuft bald ab",
    a: [
      "Im Proxy Manager unter „SSL Certificates“ beim Zertifikat auf „Renew Now“ klicken.",
      "Schlägt das fehl, muss die Domain von außen über Port 80 erreichbar sein, oder du nutzt eine DNS-Challenge.",
    ],
  },
  {
    q: "Viele Anmeldeversuche von einer Adresse",
    a: [
      "Das ist im Internet leider Alltag. Wichtig sind starke Passwörter und, wo möglich, Zwei-Faktor-Anmeldung.",
      "Sperre die Adresse mit einem Klick. Noch bequemer: Unter Administration → Sicherheit „Angreifer automatisch sperren“ einschalten.",
    ],
  },
  {
    q: "Der Agent ist offline",
    a: [
      "Im Container mit dem Proxy Manager prüfen: systemctl status networkhelper-agent",
      "Protokoll ansehen: journalctl -u networkhelper-agent -n 50",
      "Erreicht der Container NetworkHelper noch? Hat sich die IP von NetworkHelper geändert, den Installationsbefehl mit der neuen Adresse erneut ausführen.",
    ],
  },
  {
    q: "Ein neuer Dienst ist von außen nicht erreichbar",
    a: [
      "Unter DNS → Abgleich prüfen, ob für den Namen ein Eintrag existiert, sonst „Anlegen“ klicken.",
      "Neue Einträge brauchen ein paar Minuten, bis sie überall bekannt sind.",
      "Im Proxy Manager prüfen, ob der Proxy Host ein Zertifikat hat und eingeschaltet ist.",
    ],
  },
];
