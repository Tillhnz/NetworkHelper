import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, fmtAgo } from "../api.js";
import { Switch } from "../components/controls.jsx";
import { confirmDialog, Loading, toast } from "../components/feedback.jsx";
import { EmptyState, Pill } from "../components/ui.jsx";
import { InfoTip, PageIntro, Term } from "../components/help.jsx";

const TYPES = ["A", "AAAA", "CNAME", "TXT", "MX", "CAA", "SRV", "ALIAS"];

function NewRecord({ domain, onDone }) {
  const [f, setF] = useState({ name: "", type: "A", content: "", ttl: 600, dyn: true });
  const [busy, setBusy] = useState(false);
  const isA = f.type === "A";
  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post(`/dns/records/${domain}`, { ...f, ttl: Number(f.ttl), dyn: isA && f.dyn, content: isA && f.dyn ? "" : f.content });
      toast(`${f.name ? f.name + "." : ""}${domain} angelegt.`);
      setF({ name: "", type: "A", content: "", ttl: 600, dyn: true });
      onDone();
    } catch (err) { toast(err.message, "error"); } finally { setBusy(false); }
  }
  return (
    <form className="inline-form record-form" onSubmit={submit}>
      <label className="grow">Subdomain
        <span className="suffix-input"><input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="cloud" /><span>.{domain}</span></span>
      </label>
      <label>Typ<select value={f.type} onChange={(e) => setF({ ...f, type: e.target.value, content: e.target.value === "CNAME" ? domain : "" })}>{TYPES.map((t) => <option key={t}>{t}</option>)}</select></label>
      {isA && <div className="switch-cell"><Switch checked={f.dyn} onChange={(v) => setF({ ...f, dyn: v })}>Öffentliche IP (DynDNS)</Switch></div>}
      {!(isA && f.dyn) && <label className="grow">Ziel<input value={f.content} onChange={(e) => setF({ ...f, content: e.target.value })} required placeholder={f.type === "CNAME" ? domain : f.type === "TXT" ? "v=spf1 …" : ""} /></label>}
      <label>TTL<select value={f.ttl} onChange={(e) => setF({ ...f, ttl: e.target.value })}><option value="600">10 Min.</option><option value="3600">1 Std.</option><option value="86400">1 Tag</option></select></label>
      <button className="btn primary" disabled={busy}>Anlegen</button>
    </form>
  );
}

function Records({ domain, isAdmin, dynEnabled }) {
  const [d, setD] = useState(null);
  const [error, setError] = useState("");
  const load = useCallback(() => api.get(`/dns/records/${domain}`).then((r) => { setD(r); setError(""); }).catch((e) => setError(e.message)), [domain]);
  useEffect(() => { setD(null); load(); }, [load]);
  async function remove(r) {
    if (!(await confirmDialog(`${r.type}-Record ${r.fqdn} → ${r.content} bei Porkbun löschen?`))) return;
    try { await api.del(`/dns/records/${domain}/${r.id}`); toast("Gelöscht."); load(); } catch (e) { toast(e.message, "error"); }
  }
  async function dyn(r, enabled) {
    try { await api.put("/dns/dyn", { domain, name: r.name, type: r.type, enabled }); toast(enabled ? "DynDNS eingeschaltet." : "DynDNS ausgeschaltet."); load(); } catch (e) { toast(e.message, "error"); }
  }
  if (error) return <p className="error">{error}</p>;
  if (!d) return <Loading rows={2} />;
  return (
    <>
      {isAdmin && <NewRecord domain={domain} onDone={load} />}
      <div className="table-wrap flat">
        <table className="rows">
          <thead><tr><th>Name</th><th>Typ</th><th>Ziel</th><th className="hide-sm"><Term k="ttl">TTL</Term></th><th>DynDNS</th><th></th></tr></thead>
          <tbody>
            {d.records.map((r) => (
              <tr key={r.id}>
                <td className="mono"><strong>{r.name || "@"}</strong><span className="muted">{r.name ? `.${domain}` : ""}</span></td>
                <td><span className="type-tag">{r.type}</span></td>
                <td className="mono small ellipsis" title={r.content}>{r.content}</td>
                <td className="hide-sm small muted">{r.ttl}</td>
                <td>{r.type === "A" ? (isAdmin ? <Switch checked={r.dyn} onChange={(v) => dyn(r, v)}><span className="sr-only">DynDNS für {r.fqdn}</span></Switch> : r.dyn ? "ja" : "–") : ""}</td>
                <td>{isAdmin && !["NS", "SOA"].includes(r.type) && <button className="link small danger" onClick={() => remove(r)}>Löschen</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!dynEnabled && <p className="muted small">DynDNS ist unter Administration ausgeschaltet; markierte Records werden derzeit nicht nachgezogen.</p>}
    </>
  );
}

function NpmSync({ isAdmin, status }) {
  const [d, setD] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => api.get("/dns/npm").then((r) => { setD(r); setError(""); }).catch((e) => setError(e.message)), []);
  useEffect(() => { load(); }, [load]);
  async function create(fqdns) {
    setBusy(true);
    try {
      const r = await api.post("/dns/npm/create", { fqdns });
      if (r.created.length) toast(`${r.created.length} Record(s) angelegt.`);
      if (r.errors.length) toast(r.errors.join(" · "), "error");
      load();
    } catch (e) { toast(e.message, "error"); } finally { setBusy(false); }
  }
  if (error) return <p className="error small">{error}</p>;
  if (!d) return <Loading rows={1} />;
  const missing = d.items.filter((i) => i.status === "missing");
  return (
    <>
      <p className="muted small">
        Neue Records entstehen als {status.new_record_type === "CNAME" ? "CNAME auf die Hauptdomain" : "A-Record mit deiner öffentlichen IP (per DynDNS gepflegt)"}.
        {status.npm_auto_dns ? " Fehlende Records werden automatisch angelegt." : " Automatisch anlegen lässt sich unter Administration → Proxy Manager einschalten."}
      </p>
      {missing.length > 0 && isAdmin && (
        <div className="actions"><button className="btn primary" disabled={busy} onClick={() => create(missing.map((m) => m.fqdn))}>{missing.length} fehlende Records anlegen</button></div>
      )}
      <ul className="sync-list">
        {d.items.map((i) => (
          <li key={i.fqdn} className={`sync-${i.status}`}>
            <span className="sync-icon" aria-hidden="true">{i.status === "ok" ? "✓" : i.status === "missing" ? "!" : "·"}</span>
            <span className="grow"><strong className="mono">{i.fqdn}</strong><span className="muted small block">→ {i.forward}{!i.enabled && " · deaktiviert"}</span></span>
            {i.status === "ok" && <span className="muted small mono">{i.record.type} {i.record.name || "@"} → {i.record.content}</span>}
            {i.status === "missing" && (isAdmin ? <button className="btn small" disabled={busy} onClick={() => create([i.fqdn])}>Anlegen</button> : <Pill status="warn">fehlt</Pill>)}
            {i.status === "foreign" && <span className="muted small">nicht bei Porkbun verwaltet</span>}
          </li>
        ))}
      </ul>
    </>
  );
}

const FIX_TEXT = { null_mx: "MX 0 .", spf: "TXT v=spf1 -all", dmarc: "TXT _dmarc v=DMARC1; p=reject …", dmarc_monitor: "TXT _dmarc v=DMARC1; p=none", caa: 'CAA 0 issue "letsencrypt.org"' };

function Protection({ isAdmin }) {
  const [d, setD] = useState(null);
  const [busy, setBusy] = useState("");
  const load = useCallback((refresh = false) => api.get(`/dns/protection${refresh ? "?refresh=true" : ""}`).then(setD).catch((e) => toast(e.message, "error")), []);
  useEffect(() => { load(); }, [load]);
  async function fix(domain, key) {
    setBusy(domain + key);
    try { setD({ configured: true, ...(await api.post(`/dns/protection/${domain}/${key}`, {})) }); toast("Eintrag bei Porkbun angelegt."); } catch (e) { toast(e.message, "error"); } finally { setBusy(""); }
  }
  if (!d || !d.configured) return null;
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Domain-Schutz <InfoTip k="domain_guard" /></h2>
        <button className="link small" onClick={() => load(true)}>Neu prüfen</button>
      </div>
      <p className="muted small">Ohne diese Einträge kann jeder E-Mails verschicken, die scheinbar von deiner Domain kommen, zum Beispiel für Betrugsversuche in deinem Namen. Für Domains ohne eigenes Postfach reicht ein Klick.</p>
      {d.domains.map((dom) => (
        <div key={dom.domain} className="guard">
          <h3 className="sub-title">{dom.domain} {dom.error ? <Pill tone="muted">nicht lesbar</Pill> : dom.ok ? <Pill tone="ok">geschützt</Pill> : dom.open ? <Pill status="warn">{dom.open} offen</Pill> : <Pill tone="muted">Empfehlungen</Pill>}
            <span className="muted small"> · {dom.mail ? "mit E-Mail-Postfach" : "ohne E-Mail"}</span></h3>
          {dom.error && <p className="error small">{dom.error}</p>}
          <ul className="guard-list">
            {dom.checks.map((c) => (
              <li key={c.key} className={c.ok ? "ok" : c.severity === "info" ? "info" : "bad"}>
                <span className="guard-icon" aria-hidden="true">{c.ok ? "✓" : c.severity === "info" ? "○" : "✕"}</span>
                <span className="grow"><strong>{c.label}</strong><span className="muted small block">{c.detail}</span></span>
                {!c.ok && c.fix && isAdmin && (
                  <button className="btn small" disabled={busy === dom.domain + c.fix} onClick={() => fix(dom.domain, c.fix)} title={FIX_TEXT[c.fix]}>Setzen</button>
                )}
              </li>
            ))}
          </ul>
        </div>
      ))}
    </section>
  );
}

export default function Dns({ user }) {
  const isAdmin = user.role === "admin";
  const [st, setSt] = useState(null);
  const [error, setError] = useState("");
  const [domain, setDomain] = useState("");
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => api.get("/dns/status").then((s) => { setSt(s); setDomain((d) => d || s.domains[0] || ""); }).catch((e) => setError(e.message)), []);
  useEffect(() => { load(); }, [load]);

  async function runDyn() {
    setBusy(true);
    try {
      const r = await api.post("/dns/dyndns/run", {});
      toast(r.updated.length ? `Aktualisiert: ${r.updated.join(", ")}` : `Alles aktuell (IP ${r.ip || "unbekannt"}).`);
      if (r.errors.length) toast(r.errors.join(" · "), "error");
      load();
    } catch (e) { toast(e.message, "error"); } finally { setBusy(false); }
  }

  if (error) return <p className="error">{error}</p>;
  if (!st) return <Loading rows={3} />;
  const ip = st.public_ip || {};
  const last = st.dyndns_last;
  return (
    <>
      <header className="page-head"><h1>DNS</h1></header>
      <PageIntro id="dns" />
      {!st.configured ? (
        <EmptyState title="Porkbun ist noch nicht verbunden" text="Lege bei Porkbun unter Account → API Access einen Schlüssel an und schalte bei jeder Domain unter „Details“ den API-Zugriff ein. Dann trägst du beides unter Administration ein.">
          {isAdmin && <Link className="btn primary" to="/admin?tab=dns">Zur Administration</Link>}
        </EmptyState>
      ) : (
        <>
          <div className="dns-hero panel" data-tour="dns-hero">
            <div>
              <span className="eyebrow">Öffentliche IP <InfoTip k="public_ip" /></span>
              <div className="ip-big mono">{ip.ip || "unbekannt"}</div>
              <span className="muted small">{ip.source ? `ermittelt über ${ip.source}` : ""}{ip.checked_at ? `, ${fmtAgo(ip.checked_at)}` : ""}{ip.since ? ` · unverändert seit ${fmtAgo(ip.since).replace("vor ", "")}` : ""}</span>
            </div>
            <div>
              <span className="eyebrow">DynDNS <InfoTip k="dyndns" /></span>
              <div className="dyn-line">
                {st.dyndns_enabled ? <Pill status="ok">alle {st.dyndns_interval_min} Min.</Pill> : <Pill status="paused">aus</Pill>}
                <span className="muted small">{st.dyn_records.length} Record(s){last ? `, zuletzt ${fmtAgo(last.at)}` : ""}</span>
              </div>
              {st.dyn_records.some((r) => r.last_error) && <p className="error small">{st.dyn_records.filter((r) => r.last_error).map((r) => `${r.name || "@"}.${r.domain}: ${r.last_error}`).join(" · ")}</p>}
              {isAdmin && <button className="btn small" disabled={busy} onClick={runDyn}>Jetzt abgleichen</button>}
            </div>
          </div>
          {st.error && <p className="error">{st.error}</p>}
          {st.domains.length === 0 && !st.error && <p className="muted">Keine Domains gefunden. Ist bei den Domains der API-Zugriff eingeschaltet?</p>}
          {st.domains.length > 0 && (
            <section className="panel" data-tour="dns-records">
              <div className="panel-head">
                <h2><Term k="record">Records</Term></h2>
                {st.domains.length > 1 && (
                  <select value={domain} onChange={(e) => setDomain(e.target.value)} aria-label="Domain" className="auto">
                    {st.domains.map((d) => <option key={d}>{d}</option>)}
                  </select>
                )}
                {st.domains.length === 1 && <span className="mono muted">{domain}</span>}
              </div>
              {domain && <Records key={domain} domain={domain} isAdmin={isAdmin} dynEnabled={st.dyndns_enabled} />}
            </section>
          )}
        </>
      )}
      {st.configured && <Protection isAdmin={isAdmin} />}
      {st.npm_configured && (
        <section className="panel">
          <div className="panel-head"><h2>Abgleich mit dem Proxy Manager <InfoTip title="Abgleich" label="Was macht der Abgleich?">Für jeden Dienst im Proxy Manager prüft NetworkHelper, ob es bei Porkbun einen passenden Eintrag gibt. Ausrufezeichen heißt: Der Name ist noch nicht im Telefonbuch, Besucher finden den Dienst nicht. Ein Klick auf „Anlegen“ behebt das.</InfoTip></h2>
            {st.npm_sync?.at && <span className="muted small">Abgleich {fmtAgo(st.npm_sync.at)}</span>}</div>
          {st.configured ? <NpmSync isAdmin={isAdmin} status={st} /> : <p className="muted">Braucht die Porkbun-Verbindung.</p>}
        </section>
      )}
    </>
  );
}
