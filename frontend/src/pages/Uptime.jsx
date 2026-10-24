import { useCallback, useState } from "react";
import { api, fmtAgo, fmtNum } from "../api.js";
import { Sparkline, UptimeStrip } from "../components/charts.jsx";
import { Switch } from "../components/controls.jsx";
import { confirmDialog, Loading, toast } from "../components/feedback.jsx";
import { Dot, EmptyState, Pill, usePoll } from "../components/ui.jsx";

const EMPTY = { name: "", url: "https://", expect: "200-399", keyword: "", verify_tls: true, enabled: true };

function MonitorForm({ initial, onSave, onCancel, fromNpm }) {
  const [f, setF] = useState({ ...EMPTY, ...initial, keyword: initial?.keyword || "" });
  const [error, setError] = useState("");
  async function submit(e) {
    e.preventDefault();
    try { await onSave({ ...f, keyword: f.keyword || null }); } catch (err) { setError(err.message); }
  }
  return (
    <form className="form-grid monitor-form" onSubmit={submit}>
      <label>Name<input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required maxLength={120} /></label>
      <label>Adresse<input value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} required disabled={fromNpm} />
        {fromNpm && <span className="hint">Kommt aus dem Proxy Manager.</span>}</label>
      <label>Erwartete Antwort<input value={f.expect} onChange={(e) => setF({ ...f, expect: e.target.value })} placeholder="200-399" />
        <span className="hint">Statuscodes, z. B. 200-399 oder 200-299,401 für Seiten mit Anmeldung.</span></label>
      <label>Muss enthalten (optional)<input value={f.keyword} onChange={(e) => setF({ ...f, keyword: e.target.value })} placeholder="z. B. Nextcloud" /></label>
      <div className="span-all switch-row">
        <Switch checked={f.verify_tls} onChange={(v) => setF({ ...f, verify_tls: v })}>Zertifikat prüfen</Switch>
        <Switch checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })}>Aktiv</Switch>
      </div>
      {error && <p className="error span-all">{error}</p>}
      <div className="actions span-all">
        <button className="btn primary">Speichern</button>
        <button type="button" className="btn" onClick={onCancel}>Abbrechen</button>
      </div>
    </form>
  );
}

export default function Uptime({ user }) {
  const isAdmin = user.role === "admin";
  const [rows, setRows] = useState(null);
  const [error, setError] = useState("");
  const [edit, setEdit] = useState(null); // id | "new"
  const load = useCallback(() => api.get("/monitors").then((r) => { setRows(r); setError(""); }).catch((e) => setError(e.message)), []);
  usePoll(load, 20000);

  async function save(id, values) {
    if (id === "new") await api.post("/monitors", values);
    else await api.put(`/monitors/${id}`, values);
    setEdit(null);
    toast("Gespeichert.");
    load();
  }
  async function remove(m) {
    if (!(await confirmDialog(`Monitor „${m.name}“ samt Verlauf löschen?`))) return;
    try { await api.del(`/monitors/${m.id}`); load(); } catch (e) { toast(e.message, "error"); }
  }
  async function checkAll() {
    try { await api.post("/monitors/check", {}); toast("Prüfe alle Dienste …"); setTimeout(load, 5000); } catch (e) { toast(e.message, "error"); }
  }

  const down = rows?.filter((r) => r.state === "down").length || 0;
  return (
    <>
      <header className="page-head">
        <h1>Erreichbarkeit</h1>
        {isAdmin && (
          <div className="actions">
            <button className="btn" onClick={checkAll}>Jetzt prüfen</button>
            <button className="btn primary" onClick={() => setEdit("new")}>Dienst hinzufügen</button>
          </div>
        )}
      </header>
      {error && <p className="error" role="alert">{error}</p>}
      {rows && rows.length > 0 && (
        <p className={`status-banner ${down ? "is-down" : "is-up"}`}>
          <Dot tone={down ? "crit" : "ok"} pulse />{" "}
          {down ? `${down} von ${rows.length} Diensten nicht erreichbar` : `Alle ${rows.filter((r) => r.state === "up").length} Dienste erreichbar`}
        </p>
      )}
      {edit === "new" && <section className="panel"><h2>Neuer Dienst</h2><MonitorForm onSave={(v) => save("new", v)} onCancel={() => setEdit(null)} /></section>}
      {!rows ? <Loading rows={3} /> : rows.length === 0 ? (
        <EmptyState title="Noch keine Dienste" text="Verbinde den Proxy Manager unter Administration: Für jeden Proxy Host entsteht dann automatisch ein Monitor. Oder füge Adressen selbst hinzu." />
      ) : (
        <ul className="monitor-list">
          {rows.map((m) => (
            <li key={m.id} className={`panel monitor state-${m.state}`}>
              {edit === m.id ? (
                <MonitorForm initial={m} fromNpm={m.source === "npm"} onSave={(v) => save(m.id, v)} onCancel={() => setEdit(null)} />
              ) : (
                <>
                  <div className="monitor-head">
                    <div className="grow">
                      <h3><Dot tone={m.state === "up" ? "ok" : m.state === "down" ? "crit" : "muted"} pulse={m.state === "down"} /> {m.name}
                        {m.source === "npm" && <span className="muted small"> · Proxy Manager</span>}</h3>
                      <a className="muted small mono ellipsis block" href={m.url} target="_blank" rel="noreferrer noopener">{m.url}</a>
                    </div>
                    <div className="monitor-stats">
                      <span><strong>{m.uptime_24h != null ? `${fmtNum(m.uptime_24h, 2)} %` : "–"}</strong><small>24 Std.</small></span>
                      <span className="hide-sm"><strong>{m.uptime_7d != null ? `${fmtNum(m.uptime_7d, 2)} %` : "–"}</strong><small>7 Tage</small></span>
                      <span className="hide-sm"><strong>{m.uptime_30d != null ? `${fmtNum(m.uptime_30d, 2)} %` : "–"}</strong><small>30 Tage</small></span>
                      <span><strong>{m.latency_ms != null ? `${m.latency_ms} ms` : "–"}</strong><small>Antwort</small></span>
                    </div>
                  </div>
                  <UptimeStrip history={m.history} />
                  <div className="monitor-foot">
                    <span className="muted small">
                      {m.state === "paused" ? <Pill status="paused" /> : m.state === "down" ? <span className="error">{m.last_error}</span> : m.last_check ? `Zuletzt geprüft ${fmtAgo(m.last_check)}${m.last_status ? `, Antwort ${m.last_status}` : ""}` : "Noch nicht geprüft"}
                      {m.changed_at && m.state !== "paused" && ` · ${m.state === "down" ? "ausgefallen" : "erreichbar"} seit ${fmtAgo(m.changed_at).replace("vor ", "")}`}
                    </span>
                    <Sparkline values={m.history.map((h) => h.latency)} />
                    {isAdmin && (
                      <span className="rule-actions">
                        <button className="link small" onClick={() => setEdit(m.id)}>Bearbeiten</button>
                        {m.source !== "npm" && <button className="link small danger" onClick={() => remove(m)}>Löschen</button>}
                      </span>
                    )}
                  </div>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
