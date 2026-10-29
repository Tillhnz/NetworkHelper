import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, fmtAgo, fmtNum } from "../api.js";
import { confirmDialog, Loading, toast } from "./feedback.jsx";
import { EmptyState, Pill } from "./ui.jsx";
import { InfoTip } from "./help.jsx";

function Bars({ items, unit = "" }) {
  const max = Math.max(1, ...items.map((i) => i.count));
  return (
    <ul className="hbars">
      {items.map((i) => (
        <li key={i.name}><span className="hbar-label mono" title={i.name}>{i.name}</span>
          <span className="hbar-track"><span className="hbar-fill" style={{ width: `${(100 * i.count) / max}%`, background: "var(--celeste)" }} /></span>
          <span className="hbar-val">{fmtNum(i.count)}{unit}</span></li>
      ))}
    </ul>
  );
}

function Rewrites({ d, isAdmin, reload }) {
  const [f, setF] = useState({ domain: "", answer: d.suggest?.ip || "" });
  async function add(domain, answer) {
    try { await api.post("/adguard/rewrites", { domain, answer }); toast(`${domain} zeigt im Heimnetz jetzt auf ${answer}.`); reload(); } catch (e) { toast(e.message, "error"); }
  }
  async function del(r) {
    if (!(await confirmDialog(`${r.domain} → ${r.answer}`, { title: "Umschreibung löschen?", confirmLabel: "Löschen" }))) return;
    try { await api.post("/adguard/rewrites/delete", r); reload(); } catch (e) { toast(e.message, "error"); }
  }
  const s = d.suggest || {};
  return (
    <section className="panel">
      <h2>Eigene Domains im Heimnetz <InfoTip k="dns_rewrite" /></h2>
      <p className="muted small">Mit einer Umschreibung antwortet AdGuard für deine Domains zu Hause direkt mit der Adresse des Proxy Managers. Deine Seiten laden dann auch, wenn die öffentliche IP gerade wechselt oder der Router keine Verbindung „von innen nach außen und zurück“ kann.</p>
      {s.ip && (s.items?.length > 0 || s.wildcards?.length > 0) && (
        <div className="suggest">
          <p className="small"><strong>Vorschlag:</strong> {s.items.length === 1 ? "Diese Domain zeigt" : `Diese ${s.items.length} Domains zeigen`} zu Hause noch über den Router. Der Proxy Manager hat die Adresse <span className="mono">{s.ip}</span>.</p>
          <ul className="plain-list small">
            {s.wildcards?.map((w) => (
              <li key={w}><span className="grow"><span className="mono">{w}</span> <span className="muted">(alle Subdomains auf einmal, auch künftige)</span></span>{isAdmin && <button className="btn small primary" onClick={() => add(w, s.ip)}>Anlegen</button>}</li>
            ))}
            {s.items.map((n) => <li key={n}><span className="grow mono">{n}</span>{isAdmin && <button className="btn small" onClick={() => add(n, s.ip)}>Anlegen</button>}</li>)}
          </ul>
        </div>
      )}
      {s.wrong?.length > 0 && (
        <p className="small tone-warn">Zeigt woanders hin: {s.wrong.map((w) => `${w.domain} → ${w.answer}`).join(", ")}. Gewollt? Sonst auf {s.ip} ändern.</p>
      )}
      {d.rewrites.length === 0 ? <p className="muted small">Noch keine Umschreibungen.</p> : (
        <ul className="plain-list">
          {d.rewrites.map((r) => (
            <li key={r.domain + r.answer}><span className="grow"><span className="mono">{r.domain}</span> <span className="muted">→</span> <span className="mono">{r.answer}</span></span>
              {isAdmin && <button className="link small danger" onClick={() => del(r)}>Löschen</button>}</li>
          ))}
        </ul>
      )}
      {isAdmin && (
        <form className="inline-form" onSubmit={(e) => { e.preventDefault(); add(f.domain.trim(), f.answer.trim()); setF({ ...f, domain: "" }); }}>
          <label className="grow">Name<input value={f.domain} onChange={(e) => setF({ ...f, domain: e.target.value })} placeholder="nas.example.de oder *.example.de" required /></label>
          <label>Zeigt auf<input value={f.answer} onChange={(e) => setF({ ...f, answer: e.target.value })} placeholder="192.168.178.10" required /></label>
          <button className="btn">Hinzufügen</button>
        </form>
      )}
    </section>
  );
}

export default function AdGuard({ isAdmin }) {
  const [d, setD] = useState(null);
  const load = useCallback(() => api.get("/adguard").then(setD).catch((e) => toast(e.message, "error")), []);
  useEffect(() => { load(); }, [load]);

  async function protection(enabled, minutes = 0) {
    try { await api.post("/adguard/protection", { enabled, minutes }); toast(enabled ? "Schutz ist wieder an." : `Schutz für ${minutes} Minuten pausiert.`); load(); } catch (e) { toast(e.message, "error"); }
  }
  async function allow(domain) {
    if (!(await confirmDialog("AdGuard sperrt diesen Namen dann für kein Gerät mehr. Mach das nur, wenn du der Seite vertraust und dadurch etwas wieder funktioniert.", { title: `${domain} freigeben?`, confirmLabel: "Freigeben", danger: false }))) return;
    try { await api.post("/adguard/allow", { domain }); toast(`${domain} ist freigegeben.`); load(); } catch (e) { toast(e.message, "error"); }
  }

  if (!d) return <Loading rows={3} />;
  if (!d.configured) {
    return (
      <EmptyState title="AdGuard Home ist noch nicht verbunden" text="Trag unter Administration → DNS die Adresse der Weboberfläche von AdGuard Home ein (zum Beispiel http://192.168.178.53) und Benutzername und Passwort.">
        {isAdmin && <Link className="btn primary" to="/admin?tab=dns">Zur Administration</Link>}
      </EmptyState>
    );
  }
  if (d.error) {
    return (
      <section className="panel verdict verdict-crit">
        <h2>AdGuard Home antwortet nicht</h2>
        <p>{d.error}</p>
        <p className="muted small">Solange AdGuard nicht läuft, können Geräte, die ihn als DNS-Server nutzen, keine Seiten aufrufen.{d.last_ok && <> Zuletzt erreichbar {fmtAgo(d.last_ok)}.</>}</p>
      </section>
    );
  }
  const st = d.status, s = d.stats;
  const paused = !st.protection;
  return (
    <>
      <section className={`panel verdict verdict-${paused ? "warn" : d.malware.length ? "warn" : "ok"}`}>
        <div className="panel-head">
          <div>
            <h2>{paused ? "Der Schutz ist pausiert" : "AdGuard Home schützt dein Heimnetz"}</h2>
            <p className="muted">
              Version {st.version || "?"}{d.update && <> · <a href={d.update.url} target="_blank" rel="noreferrer noopener">Update auf {d.update.new_version} verfügbar</a></>}
              {" · "}{fmtNum(s.queries)} Anfragen in {s.hours >= 48 ? `${Math.round(s.hours / 24)} Tagen` : `${s.hours} Std.`}, davon {fmtNum(s.blocked_pct, 1)} % gesperrt · Antwort im Schnitt {fmtNum(s.avg_ms, 1)} ms
            </p>
            {paused && st.protection_disabled_ms > 0 && <p className="small">Geht in {Math.ceil(st.protection_disabled_ms / 60000)} Minuten automatisch wieder an.</p>}
          </div>
          {isAdmin && (paused
            ? <button className="btn primary" onClick={() => protection(true)}>Schutz einschalten</button>
            : <button className="btn" onClick={() => protection(false, 10)} title="Hilft, wenn eine Seite oder App wegen des Filters nicht funktioniert">10 Min. pausieren</button>)}
        </div>
      </section>

      <div className="kpis">
        <div className="kpi"><div className="kpi-value">{fmtNum(s.queries)}</div><div className="kpi-label">Anfragen</div></div>
        <div className="kpi"><div className="kpi-value">{fmtNum(s.blocked)}</div><div className="kpi-label">Werbung & Tracker gesperrt</div></div>
        <div className="kpi"><div className={`kpi-value ${s.malware ? "tone-warn" : ""}`}>{fmtNum(s.malware)}</div><div className="kpi-label">Schadseiten gesperrt <InfoTip k="safebrowsing" /></div></div>
        <div className="kpi"><div className="kpi-value">{fmtNum(s.parental)}</div><div className="kpi-label">Jugendschutz</div></div>
      </div>

      {d.malware.length > 0 && (
        <section className="panel">
          <h2>Gefährliche Seiten, die gesperrt wurden</h2>
          <p className="muted small">Ein einzelner Treffer ist meist ein Klick auf einen Link in einer Spam-Mail. Taucht ein Gerät oft auf, kann darauf Schadsoftware laufen.</p>
          <ul className="plain-list small">
            {d.malware.map((e, i) => <li key={i}><span className="grow"><span className="mono">{e.domain}</span> <span className="muted">· {e.client_name || e.client} · {fmtAgo(e.time)}</span></span><Pill tone="due">{e.reason_label}</Pill></li>)}
          </ul>
        </section>
      )}

      <div className="grid-2">
        <section className="panel">
          <h2>Am häufigsten gesperrt</h2>
          {s.top_blocked.length ? <Bars items={s.top_blocked} /> : <p className="muted small">Noch nichts gesperrt.</p>}
        </section>
        <section className="panel">
          <h2>Aktivste Geräte</h2>
          {s.top_clients.length ? <Bars items={s.top_clients} /> : <p className="muted small">Noch keine Anfragen.</p>}
        </section>
      </div>

      <section className="panel">
        <h2>Zuletzt gesperrt</h2>
        <p className="muted small">Funktioniert eine Seite oder App nicht, steht der Grund oft hier. Mit „Freigeben“ sperrt AdGuard den Namen nicht mehr.</p>
        {d.blocked.length === 0 ? <p className="muted small">Keine Sperren im Protokoll.</p> : (
          <div className="table-wrap flat">
            <table className="rows">
              <thead><tr><th>Name</th><th>Gerät</th><th className="hide-sm">Grund</th><th /></tr></thead>
              <tbody>
                {d.blocked.map((e, i) => (
                  <tr key={i}>
                    <td><span className="mono small">{e.domain}</span><span className="muted small block">{fmtAgo(e.time)}</span></td>
                    <td className="small">{e.client_name || e.client}</td>
                    <td className="small hide-sm">{e.reason_label}{e.rule && <span className="muted mono block ellipsis" title={e.rule}>{e.rule}</span>}</td>
                    <td>{isAdmin && <button className="link small" onClick={() => allow(e.domain)}>Freigeben</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <Rewrites d={d} isAdmin={isAdmin} reload={load} />
    </>
  );
}
