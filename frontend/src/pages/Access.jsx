import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, countryName, fmtAgo, fmtBytes, fmtCompact, fmtDate, fmtDateTime, fmtNum, fmtTime, KIND_TEXT, qs, STATUS_CLASS, statusLabel, statusText, statusTone } from "../api.js";
import { HBars, Legend, TrafficBars } from "../components/charts.jsx";
import { Segmented } from "../components/controls.jsx";
import { confirmDialog, Loading, toast } from "../components/feedback.jsx";
import { Country, Drawer, EmptyState, Kpi, Pill } from "../components/ui.jsx";
import { InfoTip, PageIntro, Term } from "../components/help.jsx";
import { MapView, ReasonBox, WhyView } from "./AccessViews.jsx";

const RANGES = [{ value: "1h", label: "1 Std." }, { value: "24h", label: "24 Std." }, { value: "7d", label: "7 Tage" }, { value: "30d", label: "30 Tage" }];
const VIEWS = [["", "Übersicht"], ["map", "Karte"], ["why", "Wer & warum"]];
const SCOPES = [{ value: "", label: "Alle" }, { value: "external", label: "Von außen" }, { value: "internal", label: "Heimnetz" }];

export function IpDetail({ ip, onClose, onFilter, isAdmin }) {
  const [d, setD] = useState(null);
  const [error, setError] = useState("");
  const load = useCallback(() => api.get(`/access/ip/${encodeURIComponent(ip)}`).then(setD).catch((e) => setError(e.message)), [ip]);
  useEffect(() => { load(); }, [load]);

  async function block(hours) {
    try {
      await api.post("/security/blocks", { cidr: ip, reason: "Manuell aus den Zugriffen", hours });
      toast(hours ? `${ip} für ${hours} Stunden gesperrt.` : `${ip} dauerhaft gesperrt.`);
      load();
    } catch (e) { toast(e.message, "error"); }
  }
  async function unblock() {
    if (!(await confirmDialog(`Sperre für ${d.blocked.cidr} aufheben?`, { confirmLabel: "Aufheben", danger: false }))) return;
    try { await api.del(`/security/blocks/${d.blocked.id}`); toast("Sperre aufgehoben."); load(); } catch (e) { toast(e.message, "error"); }
  }

  return (
    <Drawer title={ip} onClose={onClose}>
      {error && <p className="error">{error}</p>}
      {!d ? <Loading rows={2} /> : (
        <>
          <div className="ip-head">
            <Country code={d.country} org={d.as_org} />
            {d.as_org && d.as_org !== "Heimnetz" && <span className="muted">{d.as_org}{d.asn ? ` (AS${d.asn})` : ""}</span>}
            {d.blocked && <Pill tone="due">Gesperrt{d.blocked.expires_at ? ` bis ${fmtDateTime(d.blocked.expires_at)}` : ""}</Pill>}
          </div>
          <ReasonBox reason={d.reason} />
          {d.location && <p className="muted small">Ungefährer Standort: {d.location.city ? `${d.location.city}, ` : ""}{countryName(d.location.country)}</p>}
          <dl className="facts">
            <div><dt>Zugriffe (30 Tage)</dt><dd>{fmtNum(d.total)}</dd></div>
            <div><dt>Zuerst gesehen</dt><dd>{fmtDateTime(d.first)}</dd></div>
            <div><dt>Zuletzt gesehen</dt><dd>{fmtAgo(d.last)}</dd></div>
          </dl>
          <div className="actions">
            <button className="btn" onClick={() => { onFilter(ip); onClose(); }}>Nur diese IP anzeigen</button>
            {isAdmin && d.scope === "public" && !d.blocked && (
              <>
                <button className="btn danger-outline" onClick={() => block(24)}>24 Std. sperren</button>
                <button className="btn danger-outline" onClick={() => block(null)}>Dauerhaft sperren</button>
              </>
            )}
            {isAdmin && d.blocked && <button className="btn" onClick={unblock}>Sperre aufheben</button>}
            {d.scope === "public" && <a className="btn" href={`https://www.abuseipdb.com/check/${d.ip}`} target="_blank" rel="noreferrer noopener">AbuseIPDB</a>}
          </div>
          {d.incidents.length > 0 && (
            <>
              <h3 className="sub-title">Vorfälle</h3>
              <ul className="event-list">
                {d.incidents.map((i) => <li key={i.id}><Pill status={i.severity} /><span className="grow">{KIND_TEXT[i.kind]}</span><span className="muted small">{fmtNum(i.count)}× · {fmtAgo(i.last_seen)}</span></li>)}
              </ul>
            </>
          )}
          <div className="grid-2 tight">
            <div>
              <h3 className="sub-title">Ziele</h3>
              <HBars items={d.hosts.map((h) => ({ key: h.host, label: h.host, value: h.count }))} />
            </div>
            <div>
              <h3 className="sub-title">Antworten</h3>
              <HBars items={d.statuses.map((s) => ({ key: s.status, label: statusLabel(s.status), value: s.count, color: `var(--tone-${statusTone(s.status)})` }))} />
            </div>
          </div>
          {d.user_agents.length > 0 && (
            <>
              <h3 className="sub-title">Programme (User-Agent)</h3>
              <ul className="plain-list small">{d.user_agents.map((u) => <li key={u.user_agent || "-"}><span className="mono">{u.user_agent || "–"}</span> <span className="muted">{fmtNum(u.count)}×</span></li>)}</ul>
            </>
          )}
          <h3 className="sub-title">Letzte Anfragen</h3>
          <ul className="req-list">
            {d.recent.map((e) => (
              <li key={e.id}>
                <span className={`code code-${statusTone(e.status)}`} title={statusText(e.status)}>{e.status}</span>
                <span className="mono grow" title={e.path}>{e.method} {e.host}{e.path}</span>
                <span className="muted small nowrap">{fmtTime(e.ts, true)}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </Drawer>
  );
}

export default function Access({ user }) {
  const [params, setParams] = useSearchParams();
  const f = {
    range: params.get("range") || "24h", host: params.get("host") || "", ip: params.get("ip") || "", country: params.get("country") || "",
    status: params.get("status") || "", q: params.get("q") || "", scope: params.get("scope") || "", view: params.get("view") || "",
  };
  const view = f.view;
  const [data, setData] = useState(null);
  const [events, setEvents] = useState(null);
  const [next, setNext] = useState(null);
  const [hosts, setHosts] = useState([]);
  const [error, setError] = useState("");
  const [detail, setDetail] = useState(null);
  const [search, setSearch] = useState(f.q);
  const { view: _v, ...listFilters } = f;
  const key = qs(listFilters);

  const set = (patch) => {
    const n = { ...f, ...patch };
    const p = {};
    Object.entries(n).forEach(([k, v]) => { if (v && !(k === "range" && v === "24h")) p[k] = v; });
    setParams(p);
  };

  useEffect(() => { api.get("/access/hosts").then(setHosts).catch(() => {}); }, []);
  useEffect(() => {
    if (view) return undefined;
    let alive = true;
    setError("");
    Promise.all([api.get(`/access/summary${key}`), api.get(`/access/events${key}`)])
      .then(([s, e]) => { if (!alive) return; setData(s); setEvents(e.items); setNext(e.next); })
      .catch((e) => alive && setError(e.message));
    return () => { alive = false; };
  }, [key, view]);

  async function more() {
    const e = await api.get(`/access/events${qs({ ...listFilters, before_id: next })}`);
    setEvents((l) => [...l, ...e.items]);
    setNext(e.next);
  }

  const chips = [
    f.host && { k: "host", label: `Host: ${f.host}` },
    f.ip && { k: "ip", label: `IP: ${f.ip}` },
    f.country && { k: "country", label: `Land: ${f.country === "--" ? "unbekannt" : countryName(f.country)}` },
    f.status && { k: "status", label: f.status === "blocked" ? "Nur abgewiesene" : STATUS_CLASS[f.status] },
    f.q && { k: "q", label: `Pfad enthält „${f.q}“` },
  ].filter(Boolean);

  return (
    <>
      <header className="page-head">
        <h1>Zugriffe</h1>
        <Segmented value={f.range} onChange={(v) => set({ range: v })} options={RANGES} />
      </header>

      <PageIntro id="access" />
      <div className="tabs" role="tablist" aria-label="Ansicht" data-tour="access-views">
        {VIEWS.map(([k, label]) => (
          <button key={k} role="tab" aria-selected={view === k} className={`tab ${view === k ? "on" : ""}`} onClick={() => set({ view: k })}>{label}</button>
        ))}
      </div>
      {view && (
        <div className="filter-bar">
          <select value={f.host} onChange={(e) => set({ host: e.target.value })} aria-label="Host">
            <option value="">Alle Hosts</option>
            {hosts.map((h) => <option key={h} value={h}>{h}</option>)}
          </select>
        </div>
      )}
      {view === "map" && <MapView range={f.range} host={f.host} onIp={setDetail} />}
      {view === "why" && <WhyView range={f.range} host={f.host} onIp={setDetail} />}
      {!view && <>
      <div className="filter-bar" data-tour="access-filters">
        <select value={f.host} onChange={(e) => set({ host: e.target.value })} aria-label="Host">
          <option value="">Alle Hosts</option>
          {hosts.map((h) => <option key={h} value={h}>{h}</option>)}
        </select>
        <select value={f.status} onChange={(e) => set({ status: e.target.value })} aria-label="Antwort">
          <option value="">Alle Antworten</option>
          {Object.entries(STATUS_CLASS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          <option value="blocked">Abgewiesen (Sperrliste)</option>
        </select>
        <Segmented value={f.scope} onChange={(v) => set({ scope: v })} options={SCOPES} />
        <form className="search-inline" onSubmit={(e) => { e.preventDefault(); set({ q: search.trim() }); }}>
          <input type="search" placeholder="Pfad durchsuchen, z. B. /admin" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Pfad durchsuchen" />
        </form>
      </div>
      {chips.length > 0 && (
        <div className="chips">
          {chips.map((c) => <button key={c.k} className="chip on" onClick={() => { if (c.k === "q") setSearch(""); set({ [c.k]: "" }); }}>{c.label} ✕</button>)}
        </div>
      )}

      {error && <p className="error" role="alert">{error}</p>}
      {!data ? <Loading rows={3} /> : data.total === 0 && !chips.length && !f.scope ? (
        <EmptyState title="Keine Zugriffe in diesem Zeitraum" text="Die Daten kommen vom Agenten auf dem Server mit dem Nginx Proxy Manager. Ist er unter „Verbindungen“ online?" />
      ) : (
        <>
          <div className="kpis">
            <Kpi value={fmtCompact(data.total)} label="Zugriffe" />
            <Kpi value={fmtNum(data.unique_ips)} label="verschiedene IP-Adressen" />
            <Kpi value={data.total ? `${fmtNum((data.errors / data.total) * 100, 1)} %` : "–"} label="abgelehnt oder fehlgeschlagen" tone={data.errors / Math.max(1, data.total) > 0.2 ? "warn" : undefined} />
            <Kpi value={fmtNum(data.blocked)} label="abgewiesen" />
            <Kpi value={fmtBytes(data.bytes)} label="übertragen" />
          </div>

          <section className="panel" data-tour="access-chart">
            <div className="panel-head"><h2>Verlauf <InfoTip k="status_code" label="Was bedeuten die Farben?" /></h2><Legend /></div>
            <TrafficBars series={data.series} bucket={data.bucket_s} />
          </section>

          <div className="grid-3">
            <section className="panel">
              <h2>Hosts</h2>
              <HBars items={data.hosts.map((h) => ({ key: h.host, label: h.host, value: h.count, onClick: () => set({ host: h.host }) }))} />
            </section>
            <section className="panel">
              <h2>Herkunft</h2>
              <HBars color="var(--sky)" items={data.countries.map((c) => ({ key: c.country || "--", label: <Country code={c.country} />, value: c.count, onClick: () => set({ country: c.country || "--" }) }))} />
            </section>
            <section className="panel">
              <h2>Antworten <InfoTip k="status_code" /></h2>
              <HBars items={data.statuses.map((s) => ({ key: s.status, label: statusLabel(s.status), value: s.count, color: `var(--tone-${statusTone(s.status)})`, onClick: () => set({ status: String(s.status)[0] }) }))} />
            </section>
          </div>

          <div className="grid-2">
            <section className="panel" data-tour="access-ips">
              <h2>Häufigste <Term k="ip">IP-Adressen</Term></h2>
              <div className="table-wrap flat">
                <table className="rows">
                  <thead><tr><th>IP</th><th>Herkunft</th><th className="num">Zugriffe</th><th className="num">Fehler</th></tr></thead>
                  <tbody>
                    {data.ips.map((i) => (
                      <tr key={i.ip}>
                        <td className="nowrap"><button className="linklike mono" onClick={() => setDetail(i.ip)}>{i.ip}</button>
                          {i.incident && <> <Pill status="warn">Vorfall</Pill></>}{i.blocked && <> <Pill tone="due">gesperrt</Pill></>}</td>
                        <td className="nowrap"><Country code={i.country} org={i.as_org} compact /> <span className="muted small">{(i.as_org || "").slice(0, 28)}</span></td>
                        <td className="num">{fmtNum(i.count)}</td>
                        <td className={`num ${i.errors / i.count > 0.5 ? "tone-warn" : ""}`}>{fmtNum(i.errors)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
            <section className="panel">
              <h2>Häufigste Pfade</h2>
              <HBars items={data.paths.map((p) => ({ key: p.path, label: p.path, value: p.count, onClick: () => { setSearch(p.path); set({ q: p.path }); } }))} />
              <h3 className="sub-title"><Term k="asn">Netzbetreiber</Term></h3>
              <HBars color="var(--sky)" items={data.orgs.map((o) => ({ key: o.as_org || "-", label: o.as_org || "unbekannt", value: o.count }))} />
            </section>
          </div>

          <section className="panel">
            <h2>Protokoll</h2>
            {events?.length === 0 ? <p className="muted">Keine Einträge für diese Filter.</p> : (
              <div className="table-wrap flat">
                <table className="rows log-table">
                  <thead><tr><th>Zeit</th><th>Status</th><th>Anfrage</th><th>IP</th><th className="hide-sm"><Term k="user_agent">Programm</Term></th></tr></thead>
                  <tbody>
                    {events?.map((e) => (
                      <tr key={e.id} className={e.blocked ? "is-blocked" : ""}>
                        <td className="nowrap muted small">{fmtTime(e.ts, true)}<br />{fmtDate(e.ts)}</td>
                        <td><span className={`code code-${statusTone(e.status)}`} title={statusText(e.status)}>{e.status}</span></td>
                        <td className="req"><span className="muted">{e.method}</span> <strong>{e.host}</strong><span className="mono path" title={e.path}>{e.path}</span></td>
                        <td className="nowrap"><Country code={e.country} org={e.as_org} compact /> <button className="linklike mono" onClick={() => setDetail(e.ip)}>{e.ip}</button></td>
                        <td className="hide-sm muted small ellipsis ua" title={e.user_agent || ""}>{e.user_agent || "–"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {next && <div className="actions"><button className="btn" onClick={more}>Ältere laden</button></div>}
          </section>
        </>
      )}
      </>}
      {detail && <IpDetail ip={detail} onClose={() => setDetail(null)} onFilter={(ip) => set({ ip, view: "" })} isAdmin={user.role === "admin"} />}
    </>
  );
}
