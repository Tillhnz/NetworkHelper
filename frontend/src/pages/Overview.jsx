import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { api, fmtAgo, fmtCompact, fmtNum, KIND_TEXT } from "../api.js";
import { HBars, Legend, TrafficBars } from "../components/charts.jsx";
import { Loading } from "../components/feedback.jsx";
import { Country, CountUp, Dot, EmptyState, Kpi, Pill, ScoreRing, usePoll } from "../components/ui.jsx";
import { InfoTip, PageIntro, Term, useHelp } from "../components/help.jsx";

const LEVEL_TEXT = { ok: "Alles im grünen Bereich", warn: "Ein paar Dinge solltest du prüfen", crit: "Hier besteht Handlungsbedarf" };
const AREA_LINK = { ports: "/security?tab=ports", sites: "/security?tab=sites", incidents: "/security?tab=incidents", exposure: "/security?tab=exposure", uptime: "/uptime" };

/** Angebot für die Tour, solange sie noch nicht gemacht wurde. */
function TourOffer() {
  const { user, startTour, hidden, hideHint } = useHelp();
  if (user.tour_done || hidden.includes("tour-offer")) return null;
  return (
    <section className="panel tour-offer">
      <div className="grow">
        <h2>Neu hier?</h2>
        <p className="muted">Eine kurze Tour zeigt dir in zwei Minuten, wo du was findest und was die Farben und Zahlen bedeuten.</p>
      </div>
      <div className="actions">
        <button className="btn primary" onClick={startTour}>Tour starten</button>
        <button className="btn" onClick={() => hideHint("tour-offer")}>Nein danke</button>
      </div>
    </section>
  );
}

function SetupHints({ data }) {
  const hints = [];
  if (data.agents.total === 0) hints.push({ to: "/connections", text: "Agent auf dem Server mit dem Nginx Proxy Manager installieren, damit Zugriffe sichtbar werden" });
  if (!data.dns.configured) hints.push({ to: "/admin?tab=dns", text: "Porkbun-Schlüssel eintragen für DNS und DynDNS" });
  if (!data.npm_configured) hints.push({ to: "/admin?tab=npm", text: "Proxy Manager verbinden: Dienste werden dann automatisch überwacht" });
  if (!hints.length) return null;
  return (
    <section className="panel setup">
      <h2>Erste Schritte</h2>
      <ol className="setup-list">
        {hints.map((h) => <li key={h.to}><Link to={h.to}>{h.text}</Link></li>)}
      </ol>
    </section>
  );
}

export default function Overview() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const load = useCallback(() => api.get("/overview").then((d) => { setData(d); setError(""); }).catch((e) => setError(e.message)), []);
  usePoll(load, 30000);

  if (error && !data) return <p className="error" role="alert">{error}</p>;
  if (!data) return <Loading rows={4} />;
  const { access, security, monitors, certs, incidents, agents, dns, alerts } = data;
  const share = access.total ? Math.round((access.external / access.total) * 100) : 0;
  const ip = dns.public_ip?.ip;

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Übersicht</h1>
          <p className="muted small head-sub">
            <Dot tone={agents.online ? "ok" : agents.total ? "crit" : "muted"} pulse={!!agents.online} />{" "}
            {agents.total ? `${agents.online} von ${agents.total} Agenten online` : "Noch kein Agent verbunden"}
            {ip && <> · <Term k="public_ip">Öffentliche IP</Term> <code>{ip}</code></>}
          </p>
        </div>
      </header>

      <TourOffer />
      <PageIntro id="overview" />
      <SetupHints data={data} />

      <div className="hero-grid">
        <section className={`panel status-hero status-${security.level}`} data-tour="score">
          <ScoreRing score={security.score} level={security.level} />
          <div className="status-text">
            <span className="eyebrow">Sicherheitsstatus <InfoTip k="score" /></span>
            <h2>{LEVEL_TEXT[security.level]}</h2>
            {security.reasons.length === 0 ? (
              <p className="muted">Keine unerwarteten offenen Ports, gültige Zertifikate, keine offenen kritischen Vorfälle.</p>
            ) : (
              <ul className="reason-list">
                {security.reasons.slice(0, 5).map((r, i) => (
                  <li key={i} className={`reason-${r.level}`}>
                    <Link to={AREA_LINK[r.area] || "/security"}>{r.text}</Link>
                    <span className="muted small">−{r.points}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>
        <section className="panel" data-tour="services">
          <div className="panel-head"><h2>Dienste <InfoTip k="uptime" /></h2><Link className="link small" to="/uptime">Alle</Link></div>
          {monitors.total === 0 ? <p className="muted">Noch keine Dienste überwacht.</p> : (
            <>
              <p className="big-ratio"><strong><CountUp value={monitors.up} /></strong><span className="muted"> / {monitors.total} erreichbar</span></p>
              <div className="svc-dots">
                {monitors.items.map((m) => (
                  <Link key={m.id} to="/uptime" className={`svc svc-${m.state}`} title={`${m.name}: ${m.state === "up" ? `${m.latency_ms ?? "?"} ms` : m.state === "down" ? "ausgefallen" : "unbekannt"}`}>
                    <Dot tone={m.state === "up" ? "ok" : m.state === "down" ? "crit" : "muted"} /> {m.name}
                  </Link>
                ))}
              </div>
              {monitors.down.map((m) => <p key={m.id} className="error small">{m.name}: {m.error} ({fmtAgo(m.since)})</p>)}
            </>
          )}
        </section>
      </div>

      <div className="kpis" data-tour="kpis">
        <Kpi value={<CountUp value={access.total} format={fmtCompact} />} label="Zugriffe in 24 Std." sub={`${share} % von außen`} to="/access" />
        <Kpi value={<CountUp value={access.unique_ips} format={fmtNum} />} label="verschiedene IP-Adressen" to="/access" />
        <Kpi value={fmtNum(incidents.open)} label="offene Vorfälle (7 Tage)" tone={incidents.open ? "warn" : undefined} to="/security?tab=incidents" />
        <Kpi value={fmtNum(access.blocked)} label="abgewiesene Zugriffe" to="/security?tab=blocks" />
        <Kpi value={certs.next ? certs.next.days : "–"} unit={certs.next ? "Tage" : ""} label={certs.next ? `bis Zertifikat ${certs.next.host} abläuft` : "Zertifikate noch nicht geprüft"}
             tone={certs.next && certs.next.days < 14 ? "warn" : undefined} to="/security?tab=sites" />
      </div>

      <section className="panel">
        <div className="panel-head">
          <h2>Zugriffe der letzten 24 Stunden</h2>
          <Legend />
        </div>
        {access.total === 0 ? (
          <EmptyState title="Noch keine Zugriffe" text="Sobald ein Agent die Protokolle des Proxy Managers liefert, erscheinen sie hier." />
        ) : <TrafficBars series={access.series} bucket={3600} />}
      </section>

      <div className="grid-2">
        <section className="panel">
          <div className="panel-head"><h2>Meistbesucht</h2><Link className="link small" to="/access">Zugriffe</Link></div>
          {access.hosts.length ? <HBars items={access.hosts.map((h) => ({ key: h.host, label: h.host, value: h.count }))} /> : <p className="muted">–</p>}
          {access.countries.length > 0 && (
            <>
              <h3 className="sub-title">Herkunft</h3>
              <HBars color="var(--sky)" items={access.countries.map((c) => ({ key: c.country, label: <Country code={c.country} />, value: c.count }))} />
            </>
          )}
        </section>
        <section className="panel">
          <div className="panel-head"><h2>Letzte Vorfälle <InfoTip k="incident" /></h2><Link className="link small" to="/security?tab=incidents">Alle</Link></div>
          {incidents.recent.length === 0 ? <p className="muted">Keine auffälligen Zugriffe in den letzten 24 Stunden.</p> : (
            <ul className="event-list">
              {incidents.recent.map((i) => (
                <li key={i.id}>
                  <Pill status={i.severity} />
                  <span className="grow"><strong>{KIND_TEXT[i.kind] || i.kind}</strong> <span className="muted">von</span> <code>{i.ip}</code> <Country code={i.country} compact /></span>
                  <span className="muted small nowrap">{fmtNum(i.count)}× · {fmtAgo(i.last_seen)}</span>
                </li>
              ))}
            </ul>
          )}
          <div className="panel-head sub"><h3 className="sub-title">Meldungen</h3><Link className="link small" to="/alerts">Alle</Link></div>
          {alerts.length === 0 ? <p className="muted small">Noch keine Meldungen.</p> : (
            <ul className="event-list compact">
              {alerts.slice(0, 5).map((a) => (
                <li key={a.id}><Dot tone={a.severity === "crit" ? "crit" : a.severity === "warn" ? "warn" : "muted"} /><span className="grow">{a.title}</span><span className="muted small nowrap">{fmtAgo(a.created_at)}</span></li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </>
  );
}
