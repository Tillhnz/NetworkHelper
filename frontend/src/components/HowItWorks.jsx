/** Schaubild: Weg einer Anfrage aus dem Internet bis zum Dienst und wo NetworkHelper hinschaut. */
export default function HowItWorks() {
  const box = (x, y, w, h, title, sub, cls = "") => (
    <g className={`hiw-box ${cls}`}>
      <rect x={x} y={y} width={w} height={h} rx="12" />
      <text x={x + w / 2} y={y + (sub ? h / 2 - 3 : h / 2 + 5)} textAnchor="middle" className="hiw-title">{title}</text>
      {sub && <text x={x + w / 2} y={y + h / 2 + 15} textAnchor="middle" className="hiw-sub">{sub}</text>}
    </g>
  );
  return (
    <figure className="hiw">
      <svg viewBox="0 0 780 330" role="img" aria-labelledby="hiw-t hiw-d">
        <title id="hiw-t">So hängt alles zusammen</title>
        <desc id="hiw-d">Ein Besucher fragt bei Porkbun nach der Adresse deines Dienstes, kommt über deinen Router zum Nginx Proxy Manager und wird zum Dienst weitergeleitet. NetworkHelper bekommt vom Agenten die Zugriffe, prüft Router und Dienste von außen und pflegt die DNS-Einträge bei Porkbun.</desc>
        <defs>
          <marker id="hiw-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" className="hiw-arrowhead" />
          </marker>
          <marker id="hiw-arrow-nh" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" className="hiw-arrowhead-nh" />
          </marker>
        </defs>

        {/* Weg der Anfrage */}
        {box(10, 120, 120, 64, "Besucher", "Browser, App")}
        {box(200, 120, 130, 64, "Dein Router", "öffentliche IP")}
        {box(400, 120, 150, 64, "Proxy Manager", "der Pförtner", "is-proxy")}
        {box(620, 92, 150, 120, "", "")}
        <text x="695" y="118" textAnchor="middle" className="hiw-title">Deine Dienste</text>
        <text x="695" y="145" textAnchor="middle" className="hiw-sub">Nextcloud</text>
        <text x="695" y="166" textAnchor="middle" className="hiw-sub">Jellyfin</text>
        <text x="695" y="187" textAnchor="middle" className="hiw-sub">Home Assistant …</text>
        <path d="M130 152 H196" className="hiw-flow" markerEnd="url(#hiw-arrow)" />
        <path d="M330 152 H396" className="hiw-flow" markerEnd="url(#hiw-arrow)" />
        <path d="M550 152 H616" className="hiw-flow" markerEnd="url(#hiw-arrow)" />
        <text x="158" y="143" textAnchor="middle" className="hiw-label">Port 443</text>
        <text x="363" y="143" textAnchor="middle" className="hiw-label">weiter</text>
        <text x="583" y="143" textAnchor="middle" className="hiw-label">je Name</text>

        {/* DNS */}
        {box(10, 8, 140, 56, "Porkbun (DNS)", "Name → IP-Adresse")}
        <path d="M70 118 V70" className="hiw-flow thin" markerEnd="url(#hiw-arrow)" />
        <text x="78" y="92" className="hiw-label">1. Adresse</text>
        <text x="78" y="106" className="hiw-label">nachschlagen</text>

        {/* Agent auf dem Proxy Manager */}
        <g className="hiw-agent">
          <rect x="446" y="196" width="58" height="24" rx="12" />
          <text x="475" y="212" textAnchor="middle">Agent</text>
        </g>

        {/* NetworkHelper */}
        {box(400, 262, 150, 58, "NetworkHelper", "schaut auf alles", "is-nh")}
        <path d="M475 220 V258" className="hiw-nh" markerEnd="url(#hiw-arrow-nh)" />
        <text x="484" y="244" className="hiw-label nh">Zugriffe</text>
        <path d="M420 262 C420 225 265 230 265 190" className="hiw-nh" markerEnd="url(#hiw-arrow-nh)" />
        <text x="250" y="256" className="hiw-label nh">prüft offene Ports</text>
        <path d="M550 290 C695 290 695 250 695 216" className="hiw-nh" markerEnd="url(#hiw-arrow-nh)" />
        <text x="600" y="314" className="hiw-label nh">prüft Erreichbarkeit</text>
        <path d="M400 300 H206 C194 300 190 294 190 282 V50 C190 41 185 36 156 36" className="hiw-nh" markerEnd="url(#hiw-arrow-nh)" />
        <text x="204" y="290" className="hiw-label nh">trägt DNS ein (DynDNS)</text>
      </svg>
      <p className="hiw-swipe muted small" aria-hidden="true">← Zum Ansehen seitlich wischen →</p>
      <figcaption className="muted small">
        Durchgezogene Pfeile: der Weg eines Besuchers zu deinem Dienst. Gestrichelte Pfeile: was NetworkHelper dabei beobachtet und erledigt.
      </figcaption>
    </figure>
  );
}
