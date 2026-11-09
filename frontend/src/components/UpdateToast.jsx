import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api.js";

/* Update-Assistent: kleiner Hinweis unten rechts, sobald auf GitHub eine neue Version bereitliegt (nur Admins).
   Die Prüfung läuft auf dem Server höchstens stündlich; zusätzlich gibt es eine Push-Nachricht über ntfy. */

const KEY = "update-dismissed";

export default function UpdateToast() {
  const [u, setU] = useState(null);
  const [state, setState] = useState(null);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    let stop = false;
    const load = () => api.get("/admin/update/hint").then((d) => {
      if (stop || !d?.count) return;
      let seen = null;
      try { seen = localStorage.getItem(KEY); } catch { /* egal */ }
      if (seen !== d.id) setU(d);
    }).catch(() => {});
    load();
    const t = setInterval(load, 30 * 60 * 1000);
    return () => { stop = true; clearInterval(t); };
  }, []);
  if (!u) return null;
  function later() {
    try { localStorage.setItem(KEY, u.id); } catch { /* egal */ }
    setU(null);
  }
  async function install() {
    setState("running");
    try { await api.post("/admin/update"); } catch (e) { setState(e.message || "Update konnte nicht gestartet werden."); }
  }
  return (
    <div className={`update-toast${u.security ? " sec" : ""}`} role="status" aria-live="polite">
      <div className="update-toast-head">
        <span className="update-dot" aria-hidden="true" />
        <div>
          <strong>{u.security ? "Sicherheitsupdate verfügbar" : "Update verfügbar"}</strong>
          <span className="update-sub">{u.count} {u.count === 1 ? "Änderung" : "Änderungen"} · <button type="button" className="update-link" onClick={() => setOpen(!open)}>{open ? "weniger" : "Details"}</button></span>
        </div>
        <button type="button" className="update-x" aria-label="Später erinnern" onClick={later}>×</button>
      </div>
      {open && <ul className="update-list">{u.changes.map((c) => <li key={c}>{c}</li>)}</ul>}
      {state === "running" ? (
        <p className="update-sub" style={{ margin: 0 }}>Update läuft … Fortschritt unter <Link to="/admin" onClick={() => setU(null)}>Administration</Link>.</p>
      ) : (
        <>
          {state && <p className="update-err">{state}</p>}
          <div className="update-actions">
            <button type="button" className="btn" onClick={later}>Später</button>
            <button type="button" className="btn primary" onClick={install}>Jetzt aktualisieren</button>
          </div>
        </>
      )}
    </div>
  );
}
