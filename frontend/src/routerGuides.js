// Anleitungen zum Absichern des Routers. Menüpfade für die FRITZ!Box ab FRITZ!OS 7.5;
// bei älteren Versionen ggf. unten links „Ansicht: Erweitert“ einschalten.
// path: Klickweg in der Oberfläche der FRITZ!Box (http://fritz.box), steps: was dort zu tun ist.

export const ROUTERS = { fritzbox: "FRITZ!Box", other: "Anderer Router" };

export const GUIDES = {
  fritzbox: {
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
      title: "Fernwartung durch den Anbieter (TR-069)",
      why: "Über Port 7547 kann dein Internetanbieter die FRITZ!Box aus der Ferne einrichten. Meist ist das nur für seine Server erreichbar. Der eigene Scan aus dem Heimnetz zeigt den Port manchmal trotzdem. Prüfe zuerst, ob Shodan ihn auch sieht.",
      path: ["Internet", "Zugangsdaten", "Anbieter-Dienste"],
      steps: [
        "Sieht Shodan (unten auf dieser Seite) Port 7547 nicht, ist er von außen zu und du musst nichts tun. Markiere ihn dann als erwartet.",
        "Sonst: Internet → Zugangsdaten → Reiter „Anbieter-Dienste“. Der Reiter fehlt, wenn TR-069 schon aus ist.",
        "Entferne den Haken bei der Erlaubnis für den Anbieter, die FRITZ!Box einzurichten, und klicke „Übernehmen“.",
        "Achtung: Das lässt sich nur durch Zurücksetzen auf Werkseinstellungen rückgängig machen, und bei manchen Anbietern richtet sich Telefonie dann nicht mehr automatisch ein.",
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
  7547: ["tr069"],
  80: ["portforward", "remote_https"], 443: ["portforward", "remote_https"], 8443: ["remote_https", "portforward"],
  22: ["portforward", "vpn"], 2222: ["portforward", "vpn"], 8006: ["portforward", "vpn"], 8007: ["portforward", "vpn"],
  3389: ["portforward", "vpn"], 5900: ["portforward", "vpn"], 5901: ["portforward", "vpn"], 10000: ["portforward", "vpn"],
  9000: ["portforward", "vpn"], 9090: ["portforward", "vpn"], 81: ["portforward", "vpn"],
};

/** Passende Anleitungen für einen offenen Port. Unbekannte Ports: Portfreigabe und UPnP. */
export function guidesForPort(router, port) {
  const set = GUIDES[router] || GUIDES.fritzbox;
  const keys = BY_PORT[port] || ["portforward", "upnp"];
  return keys.filter((k) => set[k]).map((k) => ({ key: k, ...set[k] }));
}

/** Reihenfolge der Checkliste „Router absichern“. */
export const CHECKLIST = {
  fritzbox: ["update", "login", "portforward", "exposed", "upnp", "remote_https", "myfritz", "vpn"],
  other: ["update", "portforward", "upnp", "vpn"],
};
