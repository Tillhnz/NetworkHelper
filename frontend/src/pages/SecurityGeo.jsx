import { useCallback, useEffect, useState } from "react";
import { api, countryName, fmtAgo, fmtNum } from "../api.js";
import { Switch } from "../components/controls.jsx";
import { confirmDialog, Loading, toast } from "../components/feedback.jsx";
import { Country, Pill } from "../components/ui.jsx";
import { InfoTip } from "../components/help.jsx";

const PRESETS = [
  { label: "Nur Deutschland", countries: ["DE"] },
  { label: "DACH", countries: ["DE", "AT", "CH"] },
  { label: "EU + Schweiz", countries: ["AT", "BE", "BG", "CH", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU", "IE", "IT", "LT", "LU", "LV", "MT", "NL", "NO", "PL", "PT", "RO", "SE", "SI", "SK"] },
];

function CountryEditor({ value, onChange }) {
  const [text, setText] = useState("");
  const add = () => {
    const codes = text.toUpperCase().split(/[\s,;]+/).filter((c) => /^[A-Z]{2}$/.test(c));
    if (codes.length) onChange([...new Set([...value, ...codes])]);
    setText("");
  };
  return (
    <div className="country-editor">
      <div className="chips">
        {value.map((c) => <button type="button" key={c} className="chip on" onClick={() => onChange(value.filter((x) => x !== c))} title="Entfernen"><Country code={c} compact /> {c} ✕</button>)}
        {value.length === 0 && <span className="muted small">Noch kein Land gewählt</span>}
      </div>
      <div className="inline-form">
        <label className="grow">Land hinzufügen (zweistelliger Code, z. B. DE, AT, ES)
          <input value={text} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); add(); } }} placeholder="z. B. ES" maxLength={60} />
        </label>
        <button type="button" className="btn" onClick={add}>Hinzufügen</button>
      </div>
      <div className="actions">
        {PRESETS.map((p) => <button type="button" key={p.label} className="link small" onClick={() => onChange([...new Set([...value, ...p.countries])])}>+ {p.label}</button>)}
      </div>
    </div>
  );
}

function Preview({ p }) {
  if (!p) return null;
  return (
    <div className="geo-preview">
      <p><strong>{p.total ? `${fmtNum(p.blocked)} von ${fmtNum(p.total)} Zugriffen (${Math.round(p.share * 100)} %)` : "Keine Zugriffe"}</strong> der letzten {p.days} Tage wären abgewiesen worden (ohne Heimnetz und Let's Encrypt).</p>
      {p.countries.length > 0 && (
        <ul className="plain-list small geo-countries">
          {p.countries.slice(0, 8).map((c) => <li key={c.country}><Country code={c.country} /> <span className="muted">{fmtNum(c.count)} Zugriffe, {fmtNum(c.ips)} Adressen</span></li>)}
        </ul>
      )}
      {p.affected_users.length > 0 ? (
        <div className="notice warn small">
          <strong>Achtung, das träfe auch erwünschte Zugriffe:</strong>
          <ul className="plain-list">{p.affected_users.map((a) => <li key={a.ip}>{a.who ? `${a.who} · ` : ""}{a.label} aus {countryName(a.country)} <span className="mono muted">{a.ip}</span> ({fmtNum(a.count)}×)</li>)}</ul>
          Sind das du oder deine Familie im Ausland, nimm das Land mit auf oder nutze unterwegs ein VPN.
        </div>
      ) : p.blocked > 0 && <p className="small tone-ok">Unter den abgewiesenen Zugriffen ist nach der Erkennung von „Wer & warum“ niemand von euch.</p>}
    </div>
  );
}

export default function Geo({ isAdmin }) {
  const [d, setD] = useState(null);
  const [form, setForm] = useState({ host: "*", countries: ["DE"] });
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => api.get("/security/geo").then(setD).catch((e) => toast(e.message, "error")), []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!form.countries.length) { setPreview(null); return undefined; }
    const t = setTimeout(() => api.post("/security/geo/preview", form).then(setPreview).catch(() => {}), 300);
    return () => clearTimeout(t);
  }, [form]);

  async function add(e) {
    e.preventDefault();
    if (preview?.affected_users?.length && !(await confirmDialog("Die Regel würde auch Zugriffe abweisen, die nach eigenen Nutzern aussehen. Trotzdem anlegen?", { title: "Regel anlegen?", confirmLabel: "Anlegen", danger: false }))) return;
    setBusy(true);
    try { await api.post("/security/geo/rules", form); toast("Regel angelegt. Der Agent setzt sie innerhalb einer Minute um."); setForm({ host: "*", countries: ["DE"] }); load(); } catch (err) { toast(err.message, "error"); } finally { setBusy(false); }
  }
  async function toggle(r) {
    try { await api.put(`/security/geo/rules/${r.id}`, { host: r.host, countries: r.countries, enabled: !r.enabled }); load(); } catch (e) { toast(e.message, "error"); }
  }
  async function remove(r) {
    if (!(await confirmDialog(`Regel für ${r.host === "*" ? "alle Hosts" : r.host} löschen?`))) return;
    try { await api.del(`/security/geo/rules/${r.id}`); load(); } catch (e) { toast(e.message, "error"); }
  }
  async function feed(f, on) {
    try { await api.put("/admin/settings", { values: { [`feed_${f.key}`]: on } }); toast(on ? `${f.name} wird geladen.` : `${f.name} ausgeschaltet.`); setTimeout(load, 3000); load(); } catch (e) { toast(e.message, "error"); }
  }
  if (!d) return <Loading rows={3} />;
  const enforcing = d.agents.filter((a) => a.enforce);

  return (
    <>
      <section className={`panel verdict verdict-${enforcing.length ? "ok" : "warn"}`}>
        <h2>{enforcing.length ? "Sperren werden im Proxy Manager umgesetzt" : "Sperren sind noch nicht scharf geschaltet"}</h2>
        <p className="muted">{enforcing.length
          ? <>Umgesetzt durch {enforcing.map((a) => `${a.name}${a.status ? ` (${a.status})` : ""}`).join(", ")}. Abgewiesene Zugriffe erscheinen unter Zugriffe als „abgewiesen“.</>
          : <>Regeln und Listen wirken erst, wenn beim Agenten im Proxy-Manager-Container das Umsetzen der Sperrliste an ist. Auf diesem Server einmal ausführen: <code>curl -fsSL {window.location.origin}/api/agent/files/install.sh | bash -s -- --enforce-blocks</code>. Bis dahin kannst du alles einrichten und die Vorschau nutzen.</>}
          {d.agents.some((a) => a.version && a.version < "1.1") && " Hinweis: Ländersperren brauchen den Agenten ab Version 1.1."}</p>
      </section>

      <section className="panel">
        <h2>Länder sperren <InfoTip k="geo_block" /></h2>
        <p className="muted small">Erlaubt sind nur die gewählten Länder, alle anderen werden ohne Antwort abgewiesen. Dein Heimnetz und Let's Encrypt bleiben immer erlaubt. Eine Regel für einen Hostnamen gilt vor der Regel „alle Hosts“.</p>
        {d.rules.length > 0 && (
          <ul className="geo-rules">
            {d.rules.map((r) => (
              <li key={r.id} className={r.enabled ? "" : "paused"}>
                <span className="grow"><strong>{r.host === "*" ? "Alle Hosts" : r.host}</strong>
                  <span className="small block">nur aus: {r.countries.map((c) => countryName(c)).join(", ")}</span></span>
                {isAdmin ? (
                  <span className="rule-actions">
                    <Switch checked={r.enabled} onChange={() => toggle(r)}>{r.enabled ? "aktiv" : "aus"}</Switch>
                    <button className="link small danger" onClick={() => remove(r)}>Löschen</button>
                  </span>
                ) : <Pill tone={r.enabled ? "ok" : "muted"}>{r.enabled ? "aktiv" : "aus"}</Pill>}
              </li>
            ))}
          </ul>
        )}
        {isAdmin && (
          <form className="geo-form" onSubmit={add}>
            <h3 className="sub-title">Neue Regel</h3>
            <label>Für
              <select value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })}>
                <option value="*">Alle Hosts</option>
                {d.hosts.filter((h) => !d.rules.some((r) => r.host === h)).map((h) => <option key={h} value={h}>{h}</option>)}
              </select>
            </label>
            <div className="field-label">Erlaubte Länder</div>
            <CountryEditor value={form.countries} onChange={(countries) => setForm({ ...form, countries })} />
            <h3 className="sub-title">Vorschau</h3>
            <Preview p={preview} />
            <div className="actions"><button className="btn primary" disabled={busy || !form.countries.length || d.rules.some((r) => r.host === form.host)}>Regel anlegen</button></div>
          </form>
        )}
        {!d.geoip && <p className="small tone-warn">Die Standort-Datenbank ist ausgeschaltet (Administration → Allgemein). Ohne sie können Länder nicht erkannt werden.</p>}
      </section>

      <section className="panel">
        <h2>Öffentliche Sperrlisten</h2>
        <p className="muted small">Bekannte Angreifer-Netze werden täglich geladen und vorab abgewiesen, noch bevor sie bei dir etwas versuchen. Dein Heimnetz und deine eigene Adresse sind immer ausgenommen.</p>
        <ul className="geo-rules">
          {d.feeds.map((f) => (
            <li key={f.key}>
              <span className="grow"><strong>{f.name}</strong>
                <span className="small block muted">{f.about}</span>
                {f.enabled && <span className="small block">{f.count ? `${fmtNum(f.count)} Netze, Stand ${fmtAgo(f.fetched)}` : "wird geladen …"}{f.errors?.length ? ` · Fehler: ${f.errors[0]}` : ""}</span>}</span>
              {isAdmin ? <Switch checked={f.enabled} onChange={(on) => feed(f, on)}>{f.enabled ? "an" : "aus"}</Switch> : <Pill tone={f.enabled ? "ok" : "muted"}>{f.enabled ? "an" : "aus"}</Pill>}
            </li>
          ))}
        </ul>
      </section>
    </>
  );
}
