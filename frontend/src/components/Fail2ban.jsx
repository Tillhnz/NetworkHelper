import { useCallback, useEffect, useState } from "react";
import { api, fmtAgo, fmtNum } from "../api.js";
import { confirmDialog, Loading, toast } from "./feedback.jsx";
import { CopyLine, Country, Pill } from "./ui.jsx";
import { InfoTip } from "./help.jsx";

const installCmd = () => `curl -fsSL ${window.location.origin}/api/agent/files/install.sh | bash -s -- --fail2ban`;

/** Kurzfassung in der Server-Karte unter Verbindungen. */
export function Fail2banAgent({ agent }) {
  const f = agent.fail2ban || {};
  const old = agent.version && agent.version < "1.2";
  return (
    <div className="f2b">
      <h3 className="sub-title">fail2ban <InfoTip k="fail2ban" />{" "}
        {f.installed ? (f.running ? <Pill tone="ok">läuft</Pill> : <Pill tone="due">läuft nicht</Pill>) : <Pill tone="muted">nicht eingerichtet</Pill>}
        {f.running && f.banned > 0 && <> <Pill status="warn">{fmtNum(f.banned)} gesperrt</Pill></>}
      </h3>
      {old ? (
        <p className="muted small">Braucht den Agenten ab Version 1.2. Er aktualisiert sich gleich von selbst; danach erscheint hier der Stand.</p>
      ) : !f.installed ? (
        <>
          <p className="muted small">fail2ban sperrt Angreifer direkt in der Firewall dieses Servers, innerhalb von Sekunden: falsche SSH-Passwörter, Passwort-Raten an deinen Webseiten, Schwachstellen-Suche, falsche Proxmox-Anmeldungen. Heimnetz und deine eigene IP sind immer ausgenommen. Zum Einrichten auf dem Server einmal als root ausführen:</p>
          <CopyLine text={installCmd()} />
        </>
      ) : (
        <>
          {f.error && <p className="small tone-crit">{f.error}</p>}
          {!f.managed && f.running && <p className="muted small">fail2ban läuft mit eigener Einrichtung. Für die NetworkHelper-Regeln den Befehl oben mit <code>--fail2ban</code> ausführen.</p>}
          <ul className="plain-list small f2b-jails">
            {f.jails.map((j) => <li key={j.name}><span className="grow">{j.label}</span><span className="muted">{fmtNum(j.banned)} gesperrt · {fmtNum(j.total_banned)} insgesamt</span></li>)}
          </ul>
          <p className="muted small">Einzelne Sperren siehst und löst du unter Sicherheit → Sperrliste.</p>
        </>
      )}
    </div>
  );
}

/** Alle fail2ban-Sperren aller Server, unter Sicherheit → Sperrliste. */
export function Fail2banList({ isAdmin, onIp }) {
  const [d, setD] = useState(null);
  const load = useCallback(() => api.get("/security/fail2ban").then(setD).catch((e) => toast(e.message, "error")), []);
  useEffect(() => { load(); }, [load]);
  async function unban(ip) {
    if (!(await confirmDialog(`${ip} auf allen Servern und in der Sperrliste von NetworkHelper entsperren?`, { title: "Entsperren?", confirmLabel: "Entsperren", danger: false }))) return;
    try { const r = await api.post("/security/fail2ban/unban", { ip }); toast(`Entsperrt (${r.jails} fail2ban-Sperren, ${r.blocks_removed} in NetworkHelper). Die Server übernehmen das innerhalb einer Minute.`); setTimeout(load, 2000); } catch (e) { toast(e.message, "error"); }
  }
  if (!d) return <Loading rows={1} />;
  const withF2b = d.agents.filter((a) => a.installed);
  return (
    <section className="panel">
      <div className="panel-head"><h2>Von fail2ban gesperrt <InfoTip k="fail2ban" /></h2></div>
      {withF2b.length === 0 ? (
        <p className="muted">Auf keinem Server ist fail2ban eingerichtet. Wie das geht, steht unter Verbindungen bei jedem Server.</p>
      ) : (
        <>
          <p className="muted small">{d.share
            ? "Neue Sperren von fail2ban übernimmt NetworkHelper für 24 Stunden in seine Sperrliste. Damit gelten sie auch auf deinen anderen Servern und im Proxy Manager."
            : "Sperren von fail2ban gelten nur auf dem jeweiligen Server (Übernahme ist unter Administration → Sicherheit aus)."}</p>
          {withF2b.map((a) => (
            <div key={a.id} className="f2b-agent">
              <h3 className="sub-title">{a.name} {a.running ? <Pill tone="ok">läuft</Pill> : <Pill tone="due">läuft nicht</Pill>}
                <span className="muted small"> · Stand {fmtAgo(a.updated_at)}{a.fail2ban_version ? ` · fail2ban ${a.fail2ban_version}` : ""}</span></h3>
              {a.error && <p className="small tone-crit">{a.error}</p>}
              {a.jails.map((j) => (
                <div key={j.name} className="f2b-jail">
                  <div className="small"><strong>{j.label}</strong> <span className="muted">· {fmtNum(j.banned)} gesperrt, {fmtNum(j.total_failed)} Fehlversuche bisher</span></div>
                  {j.ips.length > 0 && (
                    <ul className="f2b-ips">
                      {j.ips.map((i) => (
                        <li key={i.ip}>
                          {i.country ? <Country code={i.country} org={i.as_org} compact /> : <span className="country" title="Land unbekannt" aria-hidden="true">🌐</span>}
                          <button className="linklike mono" onClick={() => onIp?.(i.ip)}>{i.ip}</button>
                          <span className="muted small grow">{(i.as_org || "").slice(0, 32)}</span>
                          {isAdmin && <button className="link small" onClick={() => unban(i.ip)}>Entsperren</button>}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              ))}
            </div>
          ))}
        </>
      )}
    </section>
  );
}
