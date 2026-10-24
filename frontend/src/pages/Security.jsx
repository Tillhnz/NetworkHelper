import { Fragment, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, fmtAgo, fmtDateTime, fmtNum, fmtTime } from "../api.js";
import { Switch } from "../components/controls.jsx";
import { confirmDialog, Loading, toast } from "../components/feedback.jsx";
import { Country, EmptyState, Grade, Pill } from "../components/ui.jsx";
import { IpDetail } from "./Access.jsx";
import Exposure from "./SecurityExposure.jsx";
import { InfoTip, PageIntro, Term, useHelp } from "../components/help.jsx";
import { GuideCard } from "../components/RouterGuide.jsx";
import { CHECKLIST, GUIDES, guidesForPort, ROUTERS } from "../routerGuides.js";

const TABS = [["ports", "Offene Ports"], ["router", "Router absichern"], ["sites", "Zertifikate & Header"], ["incidents", "Vorfälle"], ["exposure", "Angriffe gelungen?"], ["blocks", "Sperrliste"]];

function useWatch(load, running) {
  // Während ein Scan läuft, regelmäßig nachfragen
  useEffect(() => {
    if (!running) return undefined;
    const id = setInterval(load, 4000);
    return () => clearInterval(id);
  }, [running, load]);
}

function Ports({ isAdmin }) {
  const [d, setD] = useState(null);
  const [guideFor, setGuideFor] = useState(null);
  const [error, setError] = useState("");
  const load = useCallback(() => api.get("/security/ports").then(setD).catch((e) => setError(e.message)), []);
  useEffect(() => { load(); }, [load]);
  useWatch(load, d?.running);

  async function scan() {
    try { await api.post("/security/ports/scan", {}); toast("Scan gestartet. Das dauert etwa eine Minute."); setD((x) => ({ ...x, running: true })); } catch (e) { toast(e.message, "error"); }
  }
  async function expect(port, expected) {
    try { await api.put("/security/ports/expected", { port, expected }); load(); } catch (e) { toast(e.message, "error"); }
  }
  if (error) return <p className="error">{error}</p>;
  if (!d) return <Loading rows={2} />;
  const open = d.items.filter((p) => p.open);
  const closed = d.items.filter((p) => !p.open);
  const last = d.last;
  return (
    <>
      <section className="panel">
        <div className="panel-head">
          <h2>Von außen erreichbar <InfoTip k="open_port" /></h2>
          {isAdmin && <button className="btn" onClick={scan} disabled={d.running}>{d.running ? "Scan läuft …" : "Jetzt scannen"}</button>}
        </div>
        <p className="muted small">
          {last ? <>Letzter Scan {fmtAgo(last.finished || last.started)}: {last.targets.join(", ") || "kein Ziel"}, {fmtNum(last.ports)} Ports geprüft.</> : "Noch kein Scan gelaufen."}
          {" "}Erwartet (kein Alarm): <strong>{d.expected.join(", ") || "keine"}</strong>.
        </p>
        {last?.errors?.length > 0 && <p className="error small">{last.errors.join(" · ")}</p>}
        {open.length === 0 ? <p className="ok">Keine offenen Ports gefunden.</p> : (
          <div className="table-wrap flat">
            <table className="rows">
              <thead><tr><th>Port</th><th>Dienst</th><th>Ziel</th><th>Quelle</th><th>Seit</th><th>Erwartet <InfoTip title="Erwartet" label="Was heißt erwartet?">Ports, die du absichtlich geöffnet hast, zum Beispiel 80 und 443 für den Proxy Manager. Für erwartete Ports gibt es keinen Alarm und keinen Punktabzug. Alles andere solltest du im Router schließen, wenn du es nicht brauchst.</InfoTip></th><th><span className="sr-only">Anleitung</span></th></tr></thead>
              <tbody>
                {open.map((p) => (
                  <Fragment key={p.id}>
                  <tr className={p.expected ? "" : p.outside === "no" ? "row-info" : p.risky ? "row-crit" : "row-warn"}>
                    <td className="mono"><strong>{p.port}</strong></td>
                    <td>{p.service || "unbekannt"}{p.risky && !p.expected && p.outside !== "no" && <> <Pill tone="due">riskant</Pill></>}{p.banner && <div className="muted small mono ellipsis" title={p.banner}>{p.banner}</div>}</td>
                    <td className="mono small">{p.target}</td>
                    <td className="small">
                      <span className="nowrap">{p.source === "shodan" ? "Shodan" : "eigener Scan"}</span>
                      {p.outside === "no" && <div><Pill tone="muted">nur von innen gesehen</Pill></div>}
                      {p.outside === "yes" && p.source === "scan" && <div className="muted small">auch laut Shodan offen</div>}
                    </td>
                    <td className="small nowrap">{fmtAgo(p.first_seen)}</td>
                    <td>{isAdmin ? <Switch checked={p.expected} onChange={(v) => expect(p.port, v)}><span className="sr-only">Port {p.port} erwartet</span></Switch> : (p.expected ? "ja" : "nein")}</td>
                    <td className="nowrap">{!p.expected && (
                      <button className={`btn small ${p.risky && p.outside !== "no" ? "danger-outline" : ""}`} onClick={() => { const next = guideFor === p.id ? null : p.id; setGuideFor(next); if (next) setTimeout(() => document.getElementById("port-guide")?.scrollIntoView({ behavior: "smooth", block: "start" }), 50); }} aria-expanded={guideFor === p.id}>
                        {guideFor === p.id ? "Anleitung schließen" : p.outside === "no" ? "Wirklich offen?" : "So schließt du ihn"}
                      </button>
                    )}</td>
                  </tr>
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {(() => {
          const p = open.find((x) => x.id === guideFor);
          if (!p) return null;
          return (
            <div className="guide-for" id="port-guide">
              <h3>Port {p.port} {p.outside === "no" ? "prüfen" : "schließen"}: {p.service || "unbekannter Dienst"}</h3>
              <p className="small muted">
                Anleitung für {ROUTERS[d.router] || "deinen Router"}.
                {p.outside === "no" ? " Nur der Scan aus dem Heimnetz sieht diesen Port, Shodan von außen nicht. Wahrscheinlich antwortet nur der Router selbst."
                  : p.risky ? " Diesen Dienst solltest du nicht direkt ins Internet stellen." : " Brauchst du den Port nicht von außen, schließe ihn."}
                {" "}Ist er gewollt, schalte bei ihm „Erwartet“ ein.
              </p>
              <div className="guide-list">
                {guidesForPort(d.router, p.port, p.outside).map((g, i) => <GuideCard key={g.key} guide={g} open={i === 0} />)}
              </div>
            </div>
          );
        })()}
        {closed.length > 0 && (
          <details className="howto">
            <summary>{closed.length} früher offene Ports</summary>
            <ul className="plain-list small">{closed.map((p) => <li key={p.id}><span className="mono">{p.port}</span> {p.service} auf {p.target}, geschlossen {fmtAgo(p.closed_at)}</li>)}</ul>
            {isAdmin && <button className="link small" onClick={async () => { await api.del("/security/ports/closed"); load(); }}>Liste leeren</button>}
          </details>
        )}
      </section>
      {last?.shodan && (
        <section className="panel">
          <h2>Was <Term k="shodan">Shodan</Term> sieht</h2>
          {last.shodan.unknown ? <p className="muted">Shodan kennt deine Adresse nicht. Das ist gut: Sie wurde zuletzt nicht als offener Server erfasst.</p> : (
            <dl className="facts row">
              <div><dt>Ports</dt><dd className="mono">{last.shodan.ports.join(", ") || "keine"}</dd></div>
              <div><dt>Hostnamen</dt><dd className="small">{last.shodan.hostnames.slice(0, 4).join(", ") || "–"}</dd></div>
              <div><dt>Bekannte Schwachstellen</dt><dd className={last.shodan.vulns.length ? "tone-crit" : ""}>{last.shodan.vulns.length ? last.shodan.vulns.slice(0, 8).join(", ") : "keine"}</dd></div>
            </dl>
          )}
          <p className="muted small">Shodan durchsucht das Internet etwa wöchentlich. Der eigene Scan läuft aus deinem Heimnetz über die öffentliche Adresse (<Term k="nat_loopback">NAT-Loopback</Term>) und kann deshalb auch Ports des Routers zeigen, die von außen zu sind.</p>
        </section>
      )}
    </>
  );
}

function RouterCheck({ isAdmin }) {
  const { hidden, onUser } = useHelp();
  const [router, setRouter] = useState(null);
  useEffect(() => { api.get("/security/ports").then((d) => setRouter(d.router)).catch(() => setRouter("fritzbox")); }, []);
  if (!router) return <Loading rows={2} />;
  const keys = CHECKLIST[router] || CHECKLIST.fritzbox;
  const set = GUIDES[router] || GUIDES.fritzbox;
  const done = keys.filter((k) => hidden.includes(`router:${k}`));
  async function toggle(k) {
    const id = `router:${k}`;
    try { onUser(await api.put("/me/onboarding", hidden.includes(id) ? { unhide_hint: id } : { hide_hint: id })); } catch (e) { toast(e.message, "error"); }
  }
  async function changeRouter(v) {
    try { await api.put("/admin/settings", { values: { router_type: v } }); setRouter(v); toast("Gespeichert."); } catch (e) { toast(e.message, "error"); }
  }
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>{ROUTERS[router]} absichern</h2>
        {isAdmin && (
          <select className="auto" value={router} onChange={(e) => changeRouter(e.target.value)} aria-label="Dein Router">
            {Object.entries(ROUTERS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        )}
      </div>
      <p className="muted">
        Dein Router ist die Haustür zu deinem Heimnetz. Diese Punkte schließen die häufigsten Lücken. Klappe einen Punkt auf, um die Schritte zu sehen,
        und hake ihn ab, wenn du fertig bist. {router === "fritzbox" && <>Die Oberfläche öffnest du unter <a href="http://fritz.box" target="_blank" rel="noreferrer noopener">fritz.box</a>.</>}
      </p>
      <div className="check-progress" aria-label={`${done.length} von ${keys.length} erledigt`}>
        <div className="progress"><div className="progress-bar" style={{ width: `${(done.length / keys.length) * 100}%` }} /></div>
        <span className="small muted">{done.length} von {keys.length} erledigt</span>
      </div>
      <div className="guide-list">
        {keys.map((k) => <GuideCard key={k} guide={set[k]} done={hidden.includes(`router:${k}`)} onToggleDone={() => toggle(k)} />)}
      </div>
      {router === "fritzbox" && <p className="muted small">Die Menüpfade gelten ab FRITZ!OS 7.5. Bei älteren Versionen musst du eventuell unten links „Ansicht: Erweitert“ einschalten, damit alle Punkte sichtbar sind.</p>}
    </section>
  );
}

function Sites({ isAdmin }) {
  const [d, setD] = useState(null);
  const [open, setOpen] = useState(null);
  const [host, setHost] = useState("");
  const load = useCallback(() => api.get("/security/sites").then(setD).catch((e) => toast(e.message, "error")), []);
  useEffect(() => { load(); }, [load]);
  useWatch(load, d?.running);
  async function check() {
    try { await api.post("/security/sites/check", {}); setD((x) => ({ ...x, running: true })); toast("Prüfung gestartet."); } catch (e) { toast(e.message, "error"); }
  }
  async function add(e) {
    e.preventDefault();
    try { await api.post("/security/sites", { host }); setHost(""); toast("Hinzugefügt, die Prüfung läuft."); setTimeout(load, 4000); load(); } catch (err) { toast(err.message, "error"); }
  }
  async function toggle(s) {
    try { await api.del(`/security/sites/${encodeURIComponent(s.host)}`); load(); } catch (e) { toast(e.message, "error"); }
  }
  if (!d) return <Loading rows={2} />;
  return (
    <section className="panel">
      <div className="panel-head">
        <h2><Term k="https">Zertifikate</Term> und <Term k="headers">Sicherheits-Header</Term></h2>
        {isAdmin && <button className="btn" onClick={check} disabled={d.running}>{d.running ? "Prüfe …" : "Alle prüfen"}</button>}
      </div>
      <p className="muted small">Hostnamen aus dem Proxy Manager kommen automatisch dazu. Die <Term k="grade">Note</Term> fasst Zertifikat, TLS-Version, Weiterleitung auf HTTPS und Sicherheits-Header zusammen.</p>
      {isAdmin && (
        <form className="inline-form" onSubmit={add}>
          <label className="grow">Weiteren Hostnamen prüfen<input value={host} onChange={(e) => setHost(e.target.value)} placeholder="cloud.example.de" /></label>
          <button className="btn">Hinzufügen</button>
        </form>
      )}
      {d.items.length === 0 ? <EmptyState title="Noch nichts zu prüfen" text="Verbinde den Proxy Manager unter Administration oder füge Hostnamen hinzu." /> : (
        <ul className="site-list">
          {d.items.map((s) => (
            <li key={s.host} className={s.enabled ? "" : "paused"}>
              <button className="site-row" onClick={() => setOpen(open === s.host ? null : s.host)} aria-expanded={open === s.host}>
                <Grade grade={s.enabled ? s.grade : null} />
                <span className="grow"><strong>{s.host}</strong>
                  <span className="muted small block">{!s.enabled ? "pausiert" : s.error ? s.error : s.cert_issuer ? `${s.cert_issuer} · ${s.tls_version || ""}` : "noch nicht geprüft"}</span></span>
                {s.cert_days != null && s.enabled && <span className={`nowrap ${s.cert_days < 14 ? "tone-warn" : "muted"}`}>{s.cert_days} Tage</span>}
                <span className="muted small nowrap hide-sm">{s.checked_at ? fmtAgo(s.checked_at) : ""}</span>
              </button>
              {open === s.host && (
                <div className="site-detail">
                  <ul className="check-list">
                    {s.checks.map((c) => (
                      <li key={c.key} className={c.ok ? "ok" : "bad"}><span aria-hidden="true">{c.ok ? "✓" : "✕"}</span> {c.label} <span className="muted small mono">{c.detail}</span></li>
                    ))}
                  </ul>
                  {s.cert_expires && <p className="small muted">Zertifikat gültig bis {fmtDateTime(s.cert_expires)}</p>}
                  {!s.checks.every((c) => c.ok) && (
                    <details className="howto">
                      <summary>So behebst du fehlende Header im Proxy Manager</summary>
                      <p className="small">Proxy Host bearbeiten → „SSL“: „Force SSL“ und „HSTS Enabled“ einschalten. Unter „Advanced“ diese Zeilen eintragen:</p>
                      <pre className="code-block">{`add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;`}</pre>
                      <p className="small muted">Eine Content-Security-Policy hängt von der jeweiligen Anwendung ab und sollte zuerst vorsichtig getestet werden.</p>
                    </details>
                  )}
                  {isAdmin && <button className="link small" onClick={() => toggle(s)}>{s.source === "npm" ? (s.enabled ? "Pausieren" : "Wieder prüfen") : "Entfernen"}</button>}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function Incidents({ isAdmin, onIp }) {
  const [rows, setRows] = useState(null);
  const [openOnly, setOpenOnly] = useState(false);
  const load = useCallback(() => api.get(`/security/incidents?open_only=${openOnly}`).then(setRows).catch((e) => toast(e.message, "error")), [openOnly]);
  useEffect(() => { load(); }, [load]);
  async function ack(i) { try { await api.put(`/security/incidents/${i.id}/ack`, {}); load(); } catch (e) { toast(e.message, "error"); } }
  async function block(i) {
    try { await api.post("/security/blocks", { cidr: i.ip, reason: i.kind_text, hours: 24 * 7 }); toast(`${i.ip} für 7 Tage gesperrt.`); load(); } catch (e) { toast(e.message, "error"); }
  }
  if (!rows) return <Loading rows={2} />;
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Auffällige Zugriffe <InfoTip k="incident" /></h2>
        <div className="rule-actions">
          <Switch checked={openOnly} onChange={setOpenOnly}>Nur offene</Switch>
          {isAdmin && rows.some((r) => !r.acknowledged) && <button className="btn small" onClick={async () => { await api.post("/security/incidents/ack-all", {}); load(); }}>Alle als gesehen markieren</button>}
        </div>
      </div>
      <p className="muted small">Erkannt werden Suchen nach typischen Schwachstellen, bekannte Angriffswerkzeuge, viele fehlgeschlagene Anmeldungen (401/403), Verzeichnis-Scans (viele 404) und ungewöhnlich viele Anfragen. Gezählt wird je IP in einem Fenster von 10 Minuten.</p>
      {rows.length === 0 ? <EmptyState title="Keine Vorfälle" text="Bisher ist nichts Auffälliges passiert." /> : (
        <ul className="incident-list">
          {rows.map((i) => (
            <li key={i.id} className={i.acknowledged ? "seen" : ""}>
              <div className="incident-main">
                <Pill status={i.severity} />
                <strong>{i.kind_text}</strong>
                <button className="linklike mono" onClick={() => onIp(i.ip)}>{i.ip}</button>
                <Country code={i.country} compact /> <span className="muted small ellipsis">{i.as_org}</span>
                {i.blocked && <Pill tone="due">gesperrt</Pill>}
              </div>
              <div className="muted small">{fmtNum(i.count)} Treffer · {i.hosts.join(", ")} · {fmtDateTime(i.first_seen)} bis {fmtTime(i.last_seen)}</div>
              {i.sample.length > 0 && (
                <ul className="req-list small">
                  {i.sample.slice(-3).map((s, k) => <li key={k}><span className="code">{s.status}</span><span className="mono grow ellipsis" title={s.path}>{s.host}{s.path}</span><span className="muted ellipsis hide-sm">{s.ua}</span></li>)}
                </ul>
              )}
              {isAdmin && (
                <div className="rule-actions">
                  <button className="link small" onClick={() => ack(i)}>{i.acknowledged ? "Wieder öffnen" : "Gesehen"}</button>
                  {!i.blocked && <button className="link small danger" onClick={() => block(i)}>7 Tage sperren</button>}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function Blocks({ isAdmin }) {
  const [d, setD] = useState(null);
  const [form, setForm] = useState({ cidr: "", reason: "", hours: "" });
  const load = useCallback(() => api.get("/security/blocks").then(setD).catch((e) => toast(e.message, "error")), []);
  useEffect(() => { load(); }, [load]);
  async function add(e) {
    e.preventDefault();
    try {
      await api.post("/security/blocks", { cidr: form.cidr, reason: form.reason || null, hours: form.hours ? Number(form.hours) : null });
      setForm({ cidr: "", reason: "", hours: "" });
      toast("Gesperrt. Agenten übernehmen die Liste innerhalb von 30 Sekunden.");
      load();
    } catch (err) { toast(err.message, "error"); }
  }
  async function remove(b) {
    if (!(await confirmDialog(`Sperre für ${b.cidr} aufheben?`, { confirmLabel: "Aufheben", danger: false }))) return;
    try { await api.del(`/security/blocks/${b.id}`); load(); } catch (e) { toast(e.message, "error"); }
  }
  if (!d) return <Loading rows={2} />;
  return (
    <section className="panel">
      <h2>Sperrliste <InfoTip k="blocklist" /></h2>
      {d.enforcing_agents.length ? (
        <p className="ok small">Umgesetzt durch: {d.enforcing_agents.join(", ")}. Gesperrte Adressen bekommen vom Proxy Manager „403 Forbidden“.</p>
      ) : (
        <p className="tone-warn small">Kein Agent setzt die Sperrliste um. Führe den Installationsbefehl auf dem Proxy-Server mit <code>--enforce-blocks</code> aus, sonst ist die Liste nur ein Merkzettel.</p>
      )}
      {isAdmin && (
        <form className="inline-form" onSubmit={add}>
          <label className="grow">IP-Adresse oder Netz<input value={form.cidr} onChange={(e) => setForm({ ...form, cidr: e.target.value })} placeholder="203.0.113.7 oder 203.0.113.0/24" required /></label>
          <label className="grow">Grund<input value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} maxLength={200} /></label>
          <label>Dauer
            <select value={form.hours} onChange={(e) => setForm({ ...form, hours: e.target.value })}>
              <option value="">dauerhaft</option><option value="1">1 Stunde</option><option value="24">1 Tag</option><option value="168">1 Woche</option><option value="720">30 Tage</option>
            </select>
          </label>
          <button className="btn primary">Sperren</button>
        </form>
      )}
      {d.items.length === 0 ? <p className="muted">Keine Adressen gesperrt.</p> : (
        <div className="table-wrap flat">
          <table className="rows">
            <thead><tr><th>Adresse</th><th>Grund</th><th>Seit</th><th>Bis</th><th></th></tr></thead>
            <tbody>
              {d.items.map((b) => (
                <tr key={b.id}>
                  <td className="mono"><strong>{b.cidr}</strong>{b.auto && <> <Pill tone="muted">automatisch</Pill></>}</td>
                  <td className="small">{b.reason || "–"}</td>
                  <td className="small nowrap">{fmtDateTime(b.created_at)}</td>
                  <td className="small nowrap">{b.expires_at ? fmtDateTime(b.expires_at) : "dauerhaft"}</td>
                  <td>{isAdmin && <button className="link small" onClick={() => remove(b)}>Aufheben</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export default function Security({ user }) {
  const isAdmin = user.role === "admin";
  const [params, setParams] = useSearchParams();
  const tab = TABS.some(([k]) => k === params.get("tab")) ? params.get("tab") : "ports";
  const [ip, setIp] = useState(null);
  return (
    <>
      <header className="page-head"><h1>Sicherheit</h1></header>
      <PageIntro id="security" />
      <div className="tabs" role="tablist" aria-label="Bereiche" data-tour="security-tabs">
        {TABS.map(([k, label]) => (
          <button key={k} role="tab" aria-selected={tab === k} className={`tab ${tab === k ? "on" : ""}`} onClick={() => setParams(k === "ports" ? {} : { tab: k })}>{label}</button>
        ))}
      </div>
      {tab === "ports" && <Ports isAdmin={isAdmin} />}
      {tab === "router" && <RouterCheck isAdmin={isAdmin} />}
      {tab === "sites" && <Sites isAdmin={isAdmin} />}
      {tab === "incidents" && <Incidents isAdmin={isAdmin} onIp={setIp} />}
      {tab === "exposure" && <Exposure isAdmin={isAdmin} />}
      {tab === "blocks" && <Blocks isAdmin={isAdmin} />}
      {ip && <IpDetail ip={ip} onClose={() => setIp(null)} onFilter={(x) => { window.location.href = `/access?ip=${encodeURIComponent(x)}`; }} isAdmin={isAdmin} />}
    </>
  );
}
