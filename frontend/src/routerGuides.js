// Anleitungen zum Absichern des Routers. Menüpfade für die FRITZ!Box ab FRITZ!OS 7.5;
// bei älteren Versionen ggf. unten links „Ansicht: Erweitert“ einschalten.
// path: Klickweg in der Oberfläche der FRITZ!Box (http://fritz.box), steps: was dort zu tun ist.

export const ROUTERS = { fritzbox: "FRITZ!Box", other: "Anderer Router" };

export const GUIDES = {
  fritzbox: {
    verify: {
      title: "Erst prüfen: Ist der Port wirklich von außen offen?",
      why: "NetworkHelper scannt deine öffentliche Adresse aus dem Heimnetz. Dabei antwortet die FRITZ!Box selbst (NAT-Loopback), auch mit Diensten, die nur im Heimnetz erreichbar sind. Steht der Port nicht unter Portfreigaben und sieht Shodan ihn nicht, ist er sehr wahrscheinlich von außen geschlossen.",
      path: ["Internet", "Freigaben", "Portfreigaben"],
      steps: [
        "Schau unten auf dieser Seite in den Kasten „Was Shodan sieht“. Fehlt der Port dort, sieht ihn das Internet (Stand: letzter Shodan-Besuch) nicht.",
        "Prüfe in der FRITZ!Box unter Internet → Freigaben → Portfreigaben, ob es eine Freigabe für diesen Port gibt. Achte auch auf die Liste der per UPnP geöffneten Ports darunter.",
        "Ports, die die FRITZ!Box für sich selbst öffnet (z. B. 8089 Anbieter-Dienste, 443 MyFRITZ!, 5060 Telefonie), stehen nicht unter Portfreigaben, sondern unter Diagnose → Sicherheit.",
        "Ganz sicher wirst du mit einem Test von außen: am Handy WLAN ausschalten, mit mobilen Daten einen Online-Portscanner öffnen und deine öffentliche IP mit diesem Port prüfen.",
        "Ist der Port von außen zu, schalte bei ihm „Erwartet“ ein. Dann meldet NetworkHelper ihn nicht mehr.",
      ],
    },
    sip: {
      title: "Port 5060: Telefonie der FRITZ!Box",
      why: "Über Port 5060 (SIP) spricht die FRITZ!Box mit deinen Telefonen und dem Telefonanbieter. Das ist ihr eigener Dienst und keine Portfreigabe, deshalb taucht er unter Portfreigaben nicht auf. Meist ist er von außen gar nicht erreichbar und wird nur beim Scan aus dem Heimnetz sichtbar.",
      path: ["Telefonie", "Telefoniegeräte"],
      steps: [
        "Sieht Shodan (unten auf dieser Seite) Port 5060 nicht, ist alles in Ordnung: Schalte bei ihm „Erwartet“ ein.",
        "Prüfe unter Internet → Freigaben → Portfreigaben, dass kein Gerät eine Freigabe für 5060 hat. Die braucht nur, wer eine eigene Telefonanlage (zum Beispiel 3CX) im Heimnetz betreibt.",
        "Hast du unter Telefonie → Telefoniegeräte IP-Telefone eingerichtet, die von unterwegs (über das Internet) angemeldet sind, und brauchst du das nicht, entferne sie oder erlaube die Anmeldung nur aus dem Heimnetz.",
        "Sieht Shodan 5060 doch, wende dich an AVM oder deinen Anbieter, denn standardmäßig ist er von außen geschlossen.",
      ],
    },
    portforward: {
      title: "Portfreigabe löschen",
      why: "Eine Portfreigabe ist eine offene Tür vom Internet zu einem Gerät in deinem Heimnetz. Für deine Webdienste brauchst du nur die Freigaben für Port 80 und 443 zum Proxy Manager, alles andere solltest du schließen.",
      path: ["Internet", "Freigaben", "Portfreigaben"],
      steps: [
        "Öffne http://fritz.box im Browser und melde dich an.",
        "Gehe zu Internet → Freigaben → Reiter „Portfreigaben“. Dort steht jedes Gerät, für das Türen offen sind.",
        "Klicke beim Gerät auf den Stift (Bearbeiten). Du siehst die einzelnen Freigaben mit Portnummer.",
        "Lösche die Freigabe für den gemeldeten Port mit dem Papierkorb. Behalte nur 80 und 443 für den Proxy Manager.",
        "Unten auf „OK“ und dann „Übernehmen“ klicken. Eventuell fragt die FRITZ!Box nach einer Bestätigung am Gerät oder Telefon.",
        "In NetworkHelper unter Sicherheit → Offene Ports „Jetzt scannen“. Der Port sollte als geschlossen erscheinen.",
      ],
    },
    upnp: {
      title: "Selbstständige Portfreigaben verbieten",
      why: "Manche Geräte und Programme öffnen sich Türen im Router selbst (UPnP/PCP), ohne dass du es merkst. Steht ein unerwarteter Port offen, ist das oft die Ursache.",
      path: ["Internet", "Freigaben", "Portfreigaben", "Gerät bearbeiten"],
      steps: [
        "Gehe zu Internet → Freigaben → Portfreigaben und öffne beim betroffenen Gerät den Stift.",
        "Entferne den Haken bei „Selbstständige Portfreigaben für dieses Gerät erlauben“ und klicke „OK“.",
        "Unter der Liste stehen die per UPnP/PCP geöffneten Ports. Lösche dort unbekannte Einträge.",
        "Bei manchen FRITZ!OS-Versionen findest du die Einstellung unter Heimnetz → Netzwerk → Netzwerkverbindungen beim Gerät.",
      ],
    },
    exposed: {
      title: "Exposed Host ausschalten",
      why: "Als „Exposed Host“ ist ein Gerät komplett ungeschützt im Internet: Alle Türen stehen offen. Das sollte nie eingeschaltet sein.",
      path: ["Internet", "Freigaben", "Portfreigaben", "Gerät bearbeiten"],
      steps: [
        "Gehe zu Internet → Freigaben → Portfreigaben und öffne bei jedem Gerät den Stift.",
        "Ist bei einer Freigabe „Exposed Host“ ausgewählt, lösche diese Freigabe.",
        "Lege stattdessen nur die einzelnen Ports frei, die wirklich nötig sind (meist 80 und 443 zum Proxy Manager).",
      ],
    },
    remote_https: {
      title: "Fernzugriff auf die FRITZ!Box prüfen",
      why: "Die FRITZ!Box kann ihre eigene Oberfläche ins Internet stellen. Dann klopfen Angreifer direkt beim Router an. Wenn du das nicht unterwegs brauchst, schalte es aus, oder nutze stattdessen VPN.",
      path: ["Internet", "Freigaben", "FRITZ!Box-Dienste"],
      steps: [
        "Gehe zu Internet → Freigaben → Reiter „FRITZ!Box-Dienste“.",
        "Entferne den Haken bei „Internetzugriff auf die FRITZ!Box über HTTPS aktiviert“, wenn du ihn nicht brauchst, und klicke „Übernehmen“.",
        "Brauchst du ihn doch: Achte darauf, dass dort nicht Port 443 eingetragen ist. Den braucht der Proxy Manager. Ein zufälliger hoher Port ist üblich.",
        "Unter System → FRITZ!Box-Benutzer bei jedem Benutzer prüfen, ob „Zugang auch aus dem Internet erlaubt“ wirklich nötig ist.",
      ],
    },
    ftp: {
      title: "FTP-Zugriff aus dem Internet ausschalten",
      why: "FTP überträgt Passwörter teils unverschlüsselt und ist ein beliebtes Angriffsziel. Für Dateien von unterwegs ist eine App wie Nextcloud hinter dem Proxy Manager die bessere Wahl.",
      path: ["Internet", "Freigaben", "FRITZ!Box-Dienste"],
      steps: [
        "Gehe zu Internet → Freigaben → Reiter „FRITZ!Box-Dienste“.",
        "Entferne den Haken bei „Internetzugriff auf USB-Speicher über FTP/FTPS aktiviert“ und klicke „Übernehmen“.",
        "Prüfe außerdem unter Internet → Freigaben → Portfreigaben, ob ein Gerät eine Freigabe für Port 21 hat, und lösche sie.",
      ],
    },
    tr069: {
      title: "Port 8089/7547: Fernwartung durch den Anbieter (TR-069)",
      why: "Über diesen Port kann dein Internetanbieter die FRITZ!Box aus der Ferne einrichten (bei der FRITZ!Box meist Port 8089, sonst 7547). Die FRITZ!Box öffnet ihn selbst, sobald der Anbieter TR-069 nutzt. Es ist keine Portfreigabe, deshalb steht er nicht unter Portfreigaben. Laut AVM antwortet sie dort nur auf Anfragen mit einer vorher ausgehandelten Adresse, gibt also keine Daten an Fremde heraus.",
      path: ["Diagnose", "Sicherheit"],
      steps: [
        "Schau unter Diagnose → Sicherheit in den Abschnitt zu den aus dem Internet erreichbaren Ports. Steht dort „Anbieter-Dienste (TR-069)“ mit Port 8089, kommt die Meldung von dort.",
        "Nutzt du Telefonie und Internet von deinem Anbieter und willst nichts riskieren: Lass TR-069 an und schalte beim Port „Erwartet“ ein. Das ist vertretbar, solange die FRITZ!Box aktuell ist.",
        "Willst du den Port schließen: Internet → Zugangsdaten → Reiter „Anbieter-Dienste“ öffnen. Fehlt der Reiter, ist TR-069 schon aus.",
        "Dort den Haken bei der Erlaubnis entfernen, dass der Anbieter die FRITZ!Box einrichten darf, und auch die automatischen Firmware-Updates durch den Anbieter abschalten. Dann „Übernehmen“.",
        "Achtung: Manche Anbieter (vor allem bei gemieteten Boxen) richten Telefonie darüber ein. Wenn danach etwas nicht mehr geht, schalte es wieder ein oder frag deinen Anbieter. Zurück bekommst du die Einstellung im Zweifel nur über die Werkseinstellungen.",
      ],
    },
    vpn: {
      title: "Stattdessen per VPN von unterwegs zugreifen",
      why: "Statt Proxmox, SSH oder Datenbanken ins Internet zu stellen, verbindest du dich von unterwegs per VPN mit deinem Heimnetz. Dann ist alles erreichbar, als wärst du zu Hause, aber für Fremde bleibt die Tür zu.",
      path: ["Internet", "Freigaben", "VPN (WireGuard)"],
      steps: [
        "Gehe zu Internet → Freigaben → Reiter „VPN (WireGuard)“ (ab FRITZ!OS 7.50).",
        "Klicke „Verbindung hinzufügen“, wähle „Vereinfachte Einrichtung“ und „Einzelnes Gerät verbinden“, vergib einen Namen.",
        "Installiere die App „WireGuard“ auf dem Handy oder Laptop und scanne den angezeigten QR-Code.",
        "Unterwegs die VPN-Verbindung einschalten, dann erreichst du Proxmox wie zu Hause, etwa unter https://192.168.178.x:8006.",
        "Danach die alte Portfreigabe (zum Beispiel 8006 oder 22) löschen.",
      ],
    },
    update: {
      title: "FRITZ!OS aktuell halten",
      why: "Updates schließen Sicherheitslücken in der FRITZ!Box selbst. Am bequemsten installiert sie wichtige Updates automatisch.",
      path: ["System", "Update"],
      steps: [
        "Gehe zu System → Update → Reiter „FRITZ!OS-Version“ und klicke „Neues FRITZ!OS suchen“.",
        "Im Reiter „Auto-Update“ die Stufe wählen, bei der Updates automatisch installiert werden.",
      ],
    },
    login: {
      title: "Anmeldung an der FRITZ!Box absichern",
      why: "Wer an die Oberfläche der FRITZ!Box kommt, kann Türen öffnen. Ein eigener Benutzer mit starkem Kennwort und eine Bestätigung für wichtige Änderungen schützen davor.",
      path: ["System", "FRITZ!Box-Benutzer", "Anmeldung im Heimnetz"],
      steps: [
        "Gehe zu System → FRITZ!Box-Benutzer → Reiter „Anmeldung im Heimnetz“.",
        "Wähle „Anmeldung mit FRITZ!Box-Benutzernamen und Kennwort“ und vergib ein langes Kennwort.",
        "Lass „Ausführung bestimmter Einstellungen und Funktionen zusätzlich bestätigen“ eingeschaltet. Dann muss jede neue Portfreigabe per Taste an der Box oder am Telefon bestätigt werden.",
      ],
    },
    myfritz: {
      title: "MyFRITZ! nur nutzen, wenn du es brauchst",
      why: "MyFRITZ! macht die FRITZ!Box über das Internet erreichbar. Für deine eigenen Dienste brauchst du es nicht, dafür hast du deine Domain bei Porkbun.",
      path: ["Internet", "MyFRITZ!-Konto"],
      steps: [
        "Gehe zu Internet → MyFRITZ!-Konto.",
        "Nutzt du MyFRITZ! nicht, entferne den Haken bei „MyFRITZ! für diese FRITZ!Box verwenden“ und klicke „Übernehmen“.",
      ],
    },
  },
  other: {
    verify: {
      title: "Erst prüfen: Ist der Port wirklich von außen offen?",
      why: "NetworkHelper scannt deine öffentliche Adresse aus dem Heimnetz. Dabei antwortet der Router oft selbst, auch mit Diensten, die nur im Heimnetz erreichbar sind.",
      path: ["Router-Oberfläche", "Portfreigaben"],
      steps: [
        "Schau unten auf dieser Seite, ob Shodan den Port sieht.",
        "Prüfe in deinem Router, ob es eine Portfreigabe für diesen Port gibt.",
        "Test von außen: am Handy WLAN aus, mit mobilen Daten einen Online-Portscanner auf deine öffentliche IP und diesen Port ansetzen.",
        "Ist der Port von außen zu, schalte bei ihm „Erwartet“ ein.",
      ],
    },
    portforward: {
      title: "Portfreigabe im Router löschen",
      why: "Eine Portfreigabe ist eine offene Tür vom Internet zu einem Gerät in deinem Heimnetz. Für deine Webdienste brauchst du nur 80 und 443 zum Proxy Manager.",
      path: ["Router-Oberfläche", "Portfreigaben / Port Forwarding / NAT"],
      steps: [
        "Öffne die Oberfläche deines Routers im Browser (die Adresse steht meist unten auf dem Gerät).",
        "Suche den Bereich „Portfreigaben“, „Port Forwarding“, „NAT“ oder „Virtual Server“.",
        "Lösche die Regel für den gemeldeten Port. Behalte nur 80 und 443 zum Proxy Manager.",
        "Speichern, dann in NetworkHelper „Jetzt scannen“.",
      ],
    },
    upnp: {
      title: "UPnP ausschalten",
      why: "Mit UPnP öffnen sich Geräte selbst Türen im Router. Steht ein unerwarteter Port offen, ist das oft die Ursache.",
      path: ["Router-Oberfläche", "UPnP"],
      steps: ["Suche in der Router-Oberfläche nach „UPnP“ und schalte es aus, oder erlaube es nur für einzelne Geräte."],
    },
    vpn: {
      title: "Stattdessen per VPN zugreifen",
      why: "Statt Proxmox oder SSH ins Internet zu stellen, verbindest du dich von unterwegs per VPN mit deinem Heimnetz.",
      path: ["Router-Oberfläche", "VPN"],
      steps: [
        "Viele Router bieten WireGuard oder OpenVPN direkt an. Alternativ läuft WireGuard oder Tailscale gut in einem kleinen LXC auf Proxmox.",
        "Danach die alte Portfreigabe löschen.",
      ],
    },
    update: {
      title: "Router-Firmware aktuell halten",
      why: "Updates schließen Sicherheitslücken im Router selbst.",
      path: ["Router-Oberfläche", "Firmware / Update"],
      steps: ["Suche nach „Firmware“ oder „Update“ und schalte, wenn möglich, automatische Updates ein."],
    },
  },
};

// Welche Anleitungen zu welchem Port passen
const BY_PORT = {
  21: ["ftp", "portforward"], 990: ["ftp", "portforward"],
  5060: ["sip", "portforward"], 5061: ["sip", "portforward"],
  7547: ["tr069"], 8089: ["tr069"],
  80: ["portforward", "remote_https"], 443: ["portforward", "remote_https"], 8443: ["remote_https", "portforward"],
  22: ["portforward", "vpn"], 2222: ["portforward", "vpn"], 8006: ["portforward", "vpn"], 8007: ["portforward", "vpn"],
  3389: ["portforward", "vpn"], 5900: ["portforward", "vpn"], 5901: ["portforward", "vpn"], 10000: ["portforward", "vpn"],
  9000: ["portforward", "vpn"], 9090: ["portforward", "vpn"], 81: ["portforward", "vpn"],
};

/** Passende Anleitungen für einen offenen Port. Unbekannte Ports: Portfreigabe und UPnP. */
export function guidesForPort(router, port, outside = "unknown") {
  const set = GUIDES[router] || GUIDES.fritzbox;
  let keys = BY_PORT[port] || ["portforward", "upnp"];
  // Nur vom eigenen Scan gesehen: zuerst von außen nachprüfen
  if (outside !== "yes" && !keys.includes("sip")) keys = ["verify", ...keys];
  return keys.filter((k) => set[k]).map((k) => ({ key: k, ...set[k] }));
}

/** Reihenfolge der Checkliste „Router absichern“. */
export const CHECKLIST = {
  fritzbox: ["update", "login", "portforward", "exposed", "upnp", "remote_https", "myfritz", "vpn"],
  other: ["update", "portforward", "upnp", "vpn"],
};
