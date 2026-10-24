import { useCallback, useEffect, useState } from "react";
import { api, fmtDateTime, SEVERITY } from "../api.js";
import { Loading, toast } from "../components/feedback.jsx";
import { EmptyState, Pill } from "../components/ui.jsx";
import { PageIntro } from "../components/help.jsx";

const FILTERS = [["all", "Alle"], ["crit", SEVERITY.crit], ["warn", SEVERITY.warn], ["info", SEVERITY.info]];

export default function Alerts({ user }) {
  const isAdmin = user.role === "admin";
  const [d, setD] = useState(null);
  const [filter, setFilter] = useState("all");
  const load = useCallback(() => api.get("/alerts?limit=300").then(setD).catch((e) => toast(e.message, "error")), []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (isAdmin && d?.unread) { const id = setTimeout(() => api.post("/alerts/read", {}).catch(() => {}), 1500); return () => clearTimeout(id); }
    return undefined;
  }, [d, isAdmin]);
  async function remove(id) {
    try { await api.del(`/alerts/${id}`); load(); } catch (e) { toast(e.message, "error"); }
  }
  const items = d?.items.filter((a) => filter === "all" || a.severity === filter) || [];
  return (
    <>
      <header className="page-head"><h1>Meldungen</h1></header>
      <PageIntro id="alerts" />
      <div className="chips">
        {FILTERS.map(([k, l]) => <button key={k} className={`chip ${filter === k ? "on" : ""}`} onClick={() => setFilter(k)}>{l}</button>)}
      </div>
      {!d ? <Loading rows={3} /> : items.length === 0 ? <EmptyState title="Keine Meldungen" text="Hier ist es ruhig." /> : (
        <ul className="alert-list">
          {items.map((a) => (
            <li key={a.id} className={`panel alert-item sev-${a.severity} ${a.read ? "" : "unread"}`}>
              <div className="alert-head">
                <Pill status={a.severity} />
                <strong className="grow">{a.title}</strong>
                <span className="muted small nowrap">{fmtDateTime(a.created_at)}</span>
              </div>
              {a.body && <pre className="alert-body">{a.body}</pre>}
              <div className="alert-foot muted small">
                {a.sent_at ? (a.send_error ? `Nicht gemailt: ${a.send_error}` : `Gemailt ${fmtDateTime(a.sent_at)}`) : "Wird gleich verschickt"}
                {isAdmin && <button className="link small" onClick={() => remove(a.id)}>Entfernen</button>}
              </div>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
