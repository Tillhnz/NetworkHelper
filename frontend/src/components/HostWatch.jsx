import { useCallback, useEffect, useState } from "react";
import { api, fmtAgo, fmtDateTime } from "../api.js";
import { toast } from "./feedback.jsx";
import { Pill } from "./ui.jsx";
import { InfoTip } from "./help.jsx";

const SEV = { crit: ["wichtig", "due"], warn: ["prüfen", "soon"], info: ["Info", "muted"] };

/** Wachsamkeit eines Servers: offene Auffälligkeiten, letzte Anmeldungen, beobachtete Konten. */
export default function HostWatch({ agent, isAdmin, refreshKey }) {
  const [d, setD] = useState(null);
  const [open, setOpen] = useState(null);
  const load = useCallback(() => api.get(`/agents/${agent.id}/watch`).then(setD).catch(() => {}), [agent.id]);
  useEffect(() => { load(); }, [load, refreshKey]);

  async function ack(e) {
    try { await api.put(`/watch/events/${e.id}`, { acknowledged: true }); load(); } catch (err) { toast(err.message, "error"); }
  }
  async function ackAll() {
    try { const r = await api.post(`/agents/${agent.id}/watch/ack-all`, {}); toast(`${r.acknowledged} bestätigt.`); load(); } catch (err) { toast(err.message, "error"); }
  }
  if (!d) return null;
  const old = agent.version && agent.version < "1.1";
  if (!d.active) {
    return (
      <div className="watch">
        <h3 className="sub-title">Wachsamkeit <InfoTip k="host_watch" /></h3>
        <p className="muted small">{old
          ? `Dieser Agent ist noch Version ${agent.version} und kann sich noch nicht selbst aktualisieren. Führe auf dem Server einmal als root aus: curl -fsSL ${window.location.origin}/api/agent/files/install.sh | bash (die Einstellungen bleiben erhalten). Ab dann aktualisiert er sich selbst.`
          : "Noch kein Bericht. Der Agent schickt alle 5 Minuten, wer sich angemeldet hat, welche Konten es gibt und ob sich wichtige Systemdateien geändert haben."}</p>
      </div>
    );
  }
  return (
    <div className="watch">
      <div className="panel-head sub">
        <h3 className="sub-title">Wachsamkeit {d.open.length > 0 ? <Pill tone={d.open.some((e) => e.severity === "crit") ? "due" : "soon"}>{d.open.length} offen</Pill> : <Pill tone="ok">alles bekannt</Pill>} <InfoTip k="host_watch" /></h3>
        {isAdmin && d.open.length > 1 && <button className="link small" onClick={ackAll}>Alle bestätigen</button>}
      </div>
      {d.open.length > 0 && (
        <ul className="watch-list">
          {d.open.map((e) => {
            const [label, tone] = SEV[e.severity] || SEV.info;
            return (
              <li key={e.id} className={`sev-${e.severity}`}>
                <div className="watch-row">
                  <Pill tone={tone}>{label}</Pill>
                  <button className="linklike grow" onClick={() => setOpen(open === e.id ? null : e.id)}>{e.title}</button>
                  <span className="muted small nowrap">{fmtAgo(e.ts)}</span>
                  {isAdmin && <button className="btn small" onClick={() => ack(e)}>War ich</button>}
                </div>
                {open === e.id && e.detail && <pre className="watch-detail">{e.detail}</pre>}
              </li>
            );
          })}
        </ul>
      )}
      {d.open.length > 0 && <p className="muted small">Warst du es nicht oder bist du unsicher: Passwort ändern, unbekannte Schlüssel aus authorized_keys entfernen, unbekannte Konten löschen, im Zweifel den Container aus einer Sicherung zurückholen.</p>}
      <div className="grid-2 tight">
        <div>
          <div className="field-label">Letzte Anmeldungen</div>
          {d.logins.length === 0 ? <p className="muted small">Noch keine gesehen.</p> : (
            <ul className="plain-list small">{d.logins.slice(0, 6).map((l) => <li key={l.id}>{l.title.replace(/^(Neue )?Anmeldung (aus dem Internet: )?(als )?/, "")} <span className="muted">· {fmtDateTime(l.ts)}</span></li>)}</ul>
          )}
        </div>
        <div>
          <div className="field-label">Konten mit Anmeldung</div>
          <p className="small">{d.users.map((u) => u.name + (u.admin ? " (Admin)" : "")).join(", ") || "–"}</p>
          <p className="muted small">{d.files} wichtige Dateien unter Beobachtung{d.proxmox ? " · Proxmox-Host erkannt" : ""} · Stand {fmtAgo(d.updated_at)}</p>
        </div>
      </div>
    </div>
  );
}
