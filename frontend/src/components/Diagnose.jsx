import { useEffect, useState } from "react";
import { api, fmtAgo } from "../api.js";
import { toast } from "./feedback.jsx";
import { InfoTip } from "./help.jsx";

const ICON = { ok: "✓", fail: "✕", warn: "!", info: "i", skip: "–" };

/** Ergebnis der Fehlersuche: Urteil oben, darunter jede Station der Kette. */
export function DiagnoseResult({ res, compact = false }) {
  if (!res) return null;
  const v = res.verdict;
  return (
    <div className={`diag diag-${v.status}`}>
      <div className="diag-verdict">
        <strong>{v.title}</strong>
        <p className="small">{v.text}</p>
        {v.fix && <p className="small"><strong>So behebst du es:</strong> {v.fix}</p>}
      </div>
      {!compact && (
        <ol className="diag-steps">
          {res.steps.map((s) => (
            <li key={s.key} className={`st-${s.status}`}>
              <span className="diag-icon" aria-hidden="true">{ICON[s.status]}</span>
              <span className="grow"><strong>{s.label}</strong><span className="small block muted">{s.detail}</span>
                {s.fix && s.status !== "ok" && <span className="small block">{s.fix}</span>}</span>
            </li>
          ))}
        </ol>
      )}
      <p className="muted small">Geprüft {fmtAgo(res.checked_at)} für {res.host}</p>
    </div>
  );
}

/** Freie Fehlersuche für einen beliebigen Namen. */
export default function Diagnose({ initial = "" }) {
  const [target, setTarget] = useState(initial);
  const [hosts, setHosts] = useState([]);
  const [res, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { api.get("/diagnose/hosts").then(setHosts).catch(() => {}); }, []);
  useEffect(() => { if (initial) run(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  async function run(e) {
    e?.preventDefault();
    if (!target.trim()) return;
    setBusy(true); setRes(null);
    try { setRes(await api.post("/diagnose", { target: target.trim() })); } catch (err) { toast(err.message, "error"); } finally { setBusy(false); }
  }
  return (
    <section className="panel">
      <h2>Warum ist ein Dienst nicht erreichbar? <InfoTip k="diagnose" /></h2>
      <p className="muted small">NetworkHelper prüft die ganze Kette, die ein Besucher durchläuft: Name im Internet, deine IP, Router, Zertifikat, Proxy Manager und der Dienst dahinter. Er nennt die erste Stelle, an der es hakt, und wie du es behebst.</p>
      <form className="inline-form" onSubmit={run}>
        <label className="grow">Adresse
          <input list="diag-hosts" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="cloud.example.de" />
          <datalist id="diag-hosts">{hosts.map((h) => <option key={h} value={h} />)}</datalist>
        </label>
        <button className="btn primary" disabled={busy || !target.trim()}>{busy ? "Prüfe … (bis zu 30 Sek.)" : "Ursache suchen"}</button>
      </form>
      <DiagnoseResult res={res} />
    </section>
  );
}
