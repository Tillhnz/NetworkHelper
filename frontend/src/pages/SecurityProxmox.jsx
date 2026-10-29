import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, fmtAgo, fmtNum } from "../api.js";
import { Loading, toast } from "../components/feedback.jsx";
import { EmptyState, Pill } from "../components/ui.jsx";
import { InfoTip } from "../components/help.jsx";

const LEVEL = { crit: ["kritisch", "due"], warn: ["wichtig", "soon"], info: ["Hinweis", "muted"] };

function Check({ c }) {
  const [text, tone] = LEVEL[c.level] || LEVEL.info;
  return (
    <li className={`pve-check lvl-${c.level}`}>
      <Pill tone={tone}>{text}</Pill>
      <span className="grow">{c.text}<span className="muted small block">{c.fix}</span></span>
    </li>
  );
}

const days = (iso) => (iso ? Math.floor((Date.now() - new Date(iso + "Z").getTime()) / 86400000) : null);

export default function Proxmox({ isAdmin }) {
  const [d, setD] = useState(null);
  const [open, setOpen] = useState(null);
  const load = useCallback(() => api.get("/security/proxmox").then(setD).catch((e) => toast(e.message, "error")), []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!d?.running) return undefined;
    const id = setInterval(load, 3000);
    return () => clearInterval(id);
  }, [d?.running, load]);
  async function check() {
    try { await api.post("/security/proxmox/check", {}); setD((x) => ({ ...x, running: true })); } catch (e) { toast(e.message, "error"); }
  }
  if (!d) return <Loading rows={3} />;
  if (!d.configured || !d.pinned) {
    return (
      <EmptyState title={d.configured ? "Zertifikat noch nicht bestätigt" : "Proxmox ist noch nicht verbunden"}
        text="Mit einem API-Token, das nur lesen darf, sieht NetworkHelper alle Container und VMs: Wer ist privilegiert, wann war die letzte Sicherung, welche Sicherheitsupdates fehlen, wurde ein neues Konto angelegt?">
        {isAdmin && <Link className="btn primary" to="/admin?tab=proxmox">Einrichten</Link>}
      </EmptyState>
    );
  }
  const snap = d.data;
  const guestIssues = snap ? snap.guests.flatMap((g) => g.checks.filter((c) => c.level !== "info")) : [];
  const hostIssues = snap ? snap.host_checks.filter((c) => c.level !== "info") : [];
  const crit = [...guestIssues, ...hostIssues].filter((c) => c.level === "crit").length;
  const n = guestIssues.length + hostIssues.length;
  const tone = !snap ? "info" : crit ? "crit" : n ? "warn" : "ok";
  return (
    <>
      <section className={`panel verdict verdict-${tone}`}>
        <div className="panel-head">
          <div>
            <h2>{!snap ? "Noch keine Daten" : crit ? `${crit} kritische ${crit === 1 ? "Sache" : "Sachen"} auf deinem Proxmox` : n ? `${n} ${n === 1 ? "Punkt" : "Punkte"} zum Verbessern` : "Proxmox sieht gut aus"} <InfoTip k="proxmox" /></h2>
            <p className="muted">
              {snap && <>Proxmox VE {snap.version} · {snap.guests.filter((g) => !g.template).length} Gäste, {snap.guests.filter((g) => g.status === "running").length} laufen · geprüft {fmtAgo(snap.checked_at)}. </>}
              Nur lesender Zugriff.
            </p>
            {d.error && <p className="error small">{d.error.error}</p>}
          </div>
          {isAdmin && <button className="btn primary" onClick={check} disabled={d.running}>{d.running ? "Prüfe …" : "Jetzt prüfen"}</button>}
        </div>
      </section>
      {snap && (
        <>
          {snap.host_checks.length > 0 && (
            <section className="panel">
              <h2>Host</h2>
              <ul className="plain-list">{snap.host_checks.map((c, i) => <Check key={i} c={c} />)}</ul>
            </section>
          )}
          <section className="panel">
            <h2>Container und VMs</h2>
            <ul className="plain-list pve-guests">
              {snap.guests.map((g) => {
                const bad = g.checks.filter((c) => c.level !== "info");
                const age = days(g.backup_at);
                return (
                  <li key={g.vmid}>
                    <button className="pve-row" onClick={() => setOpen(open === g.vmid ? null : g.vmid)} aria-expanded={open === g.vmid}>
                      <span className={`dot ${g.status === "running" ? "dot-ok" : "dot-muted"}`} aria-hidden="true" />
                      <span className="grow"><strong>{g.name}</strong> <span className="muted small">{g.vmid} · {g.type === "lxc" ? "Container" : "VM"}{g.template ? " · Vorlage" : ""}{g.status !== "running" ? " · gestoppt" : ""}</span>
                        <span className="muted small block">
                          {g.type === "lxc" && (g.unprivileged ? "unprivilegiert" : "privilegiert")}{g.type === "lxc" && " · "}
                          Sicherung: {age == null ? "keine" : age === 0 ? "heute" : `vor ${age} ${age === 1 ? "Tag" : "Tagen"}`}
                          {" · "}{g.agent ? `Agent ${g.agent.online ? "aktiv" : "offline"}` : "kein Agent"}
                        </span></span>
                      {bad.length ? <Pill tone={bad.some((c) => c.level === "crit") ? "due" : "soon"}>{bad.length} {bad.length === 1 ? "Punkt" : "Punkte"}</Pill> : <Pill tone="ok">ok</Pill>}
                    </button>
                    {open === g.vmid && (
                      <div className="pve-detail">
                        {g.checks.length ? <ul className="plain-list">{g.checks.map((c, i) => <Check key={i} c={c} />)}</ul> : <p className="muted small">Keine Auffälligkeiten.</p>}
                        {!g.agent && !g.template && <p className="small muted">Tipp: Mit dem Agenten in diesem Gast siehst du auch Anmeldungen und veränderte Systemdateien (Verbindungen → Agent hinzufügen).</p>}
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          </section>
          <div className="grid-2">
            <section className="panel">
              <h2>Knoten</h2>
              <ul className="plain-list small">
                {snap.nodes.map((nd) => (
                  <li key={nd.name}><span className="grow"><strong>{nd.name}</strong>
                    <span className="muted block">{nd.online ? <>Proxmox {nd.pve}{nd.kernel && <> · Kernel {nd.kernel}</>}{nd.maxmem > 0 && <> · RAM {fmtNum(100 * nd.mem / nd.maxmem, 0)} %</>}</> : "offline"}</span></span>
                    {nd.online && (nd.security_updates ? <Pill tone="due">{nd.security_updates} {nd.security_updates === 1 ? "Sicherheitsupdate" : "Sicherheitsupdates"}</Pill> : nd.updates ? <Pill tone="soon">{nd.updates} Updates</Pill> : <Pill tone="ok">aktuell</Pill>)}</li>
                ))}
              </ul>
            </section>
            <section className="panel">
              <h2>Konten mit Zugang</h2>
              <ul className="plain-list small">
                {snap.users.map((u) => (
                  <li key={u.user}><span className="grow mono">{u.user}<span className="muted block">{u.comment || ""}{u.tokens ? ` ${u.tokens} API-Token` : ""}</span></span>
                    {u.has_tfa == null ? null : u.has_tfa ? <Pill tone="ok">2FA</Pill> : <Pill tone="soon">ohne 2FA</Pill>}</li>
                ))}
              </ul>
              <p className="muted small">Neue Konten und neue API-Tokens meldet NetworkHelper sofort.</p>
            </section>
          </div>
        </>
      )}
    </>
  );
}
