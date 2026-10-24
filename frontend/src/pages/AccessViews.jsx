import { useEffect, useMemo, useState } from "react";
import { api, countryName, fmtAgo, fmtNum, qs } from "../api.js";
import { HBars } from "../components/charts.jsx";
import { Loading } from "../components/feedback.jsx";
import { Country, EmptyState } from "../components/ui.jsx";
import { InfoTip, Term } from "../components/help.jsx";
import WorldMap, { GROUP_COLORS, GROUP_ORDER } from "../components/WorldMap.jsx";

const GROUP_HINT = {
  friendly: "Das bist du, deine Familie oder deine Apps.",
  service: "Dienste, die du brauchst oder die deine Seiten bekannt machen.",
  noise: "Automatische Abfragen aus dem Internet. Normal für jeden erreichbaren Server.",
  attack: "Sucht nach Lücken oder rät Passwörter. Die Sperrliste hält sie auf.",
};

function GroupToggles({ groups, counts, hidden, onToggle }) {
  return (
    <div className="group-toggles" role="group" aria-label="Gruppen ein- und ausblenden">
      {GROUP_ORDER.map((g) => (
        <button key={g} type="button" className={`chip ${hidden.includes(g) ? "" : "on"} grp-chip`} aria-pressed={!hidden.includes(g)} onClick={() => onToggle(g)}>
          <span className="swatch" style={{ background: GROUP_COLORS[g] }} />
          {groups[g]} <span className="muted">{fmtNum(counts[g] || 0)}</span>
        </button>
      ))}
    </div>
  );
}

export function MapView({ range, host, onIp }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [hidden, setHidden] = useState([]);
  const [sel, setSel] = useState(null);

  useEffect(() => {
    let alive = true;
    setData(null); setSel(null); setError("");
    api.get(`/access/map${qs({ range, host })}`).then((d) => alive && setData(d)).catch((e) => alive && setError(e.message));
    return () => { alive = false; };
  }, [range, host]);

  const counts = useMemo(() => {
    const c = {};
    (data?.points || []).forEach((p) => Object.entries(p.groups).forEach(([g, n]) => { c[g] = (c[g] || 0) + n; }));
    return c;
  }, [data]);

  if (error) return <p className="error" role="alert">{error}</p>;
  if (!data) return <Loading rows={3} />;
  if (!data.points.length) {
    return <EmptyState title="Noch nichts auf der Karte" text={data.unplaced ? "Es gab Zugriffe von außen, aber ihr Standort ist unbekannt. Die Standort-Datenbank wird beim ersten Start geladen; das kann ein paar Minuten dauern." : "In diesem Zeitraum kamen keine Zugriffe aus dem Internet. Zugriffe aus deinem Heimnetz zeigt die Karte nicht."} />;
  }
  const toggle = (g) => setHidden((h) => (h.includes(g) ? h.filter((x) => x !== g) : [...h, g]));
  const total = Object.values(counts).reduce((a, b) => a + b, 0);

  return (
    <>
      <section className="panel map-panel" data-tour="access-map">
        <div className="panel-head">
          <h2>Woher die Zugriffe kommen <InfoTip k="geo_map" /></h2>
          <GroupToggles groups={data.groups} counts={counts} hidden={hidden} onToggle={toggle} />
        </div>
        <div className="map-layout">
          <WorldMap points={data.points} countries={data.countries} home={data.home} hidden={hidden} selected={sel} onSelect={setSel} />
          <aside className="map-side">
            {sel ? <PlaceDetail p={sel} onIp={onIp} onClose={() => setSel(null)} /> : (
              <>
                <h3 className="sub-title">Länder</h3>
                <HBars color="var(--sky)" items={data.countries.filter((c) => c.country !== "--").slice(0, 10).map((c) => ({ key: c.country, label: <Country code={c.country} />, value: c.count }))} />
                <p className="muted small">
                  {fmtNum(total)} Zugriffe von {fmtNum(data.ips)} Adressen{data.unplaced ? `, ${fmtNum(data.unplaced)} ohne bekannten Standort` : ""}.
                  {" "}Tippe auf einen Punkt, um zu sehen, wer dort sitzt.
                </p>
                {!data.city_db && <p className="muted small">Ohne Städtedatenbank stehen die Punkte in der Landesmitte. Admins können die Städte unter Administration → Allgemein einschalten.</p>}
              </>
            )}
          </aside>
        </div>
      </section>
      <p className="muted small map-note">
        Standorte von IP-Adressen sind Schätzungen: Oft zeigt die Datenbank den Sitz des Anbieters statt des Geräts. Mobilfunk landet gern in Frankfurt oder Düsseldorf,
        VPN-Nutzer im Land ihres VPN-Servers. Deine eigenen Zugriffe aus dem Heimnetz sind nicht eingezeichnet.
      </p>
    </>
  );
}

function PlaceDetail({ p, onIp, onClose }) {
  return (
    <div className="place-detail">
      <div className="place-head">
        <h3 className="sub-title">{p.city ? `${p.city}, ` : ""}{countryName(p.country)}</h3>
        <button className="btn icon" onClick={onClose} aria-label="Auswahl schließen">✕</button>
      </div>
      <p className="muted small">{fmtNum(p.count)} Zugriffe von {fmtNum(p.ips)} {p.ips === 1 ? "Adresse" : "Adressen"}</p>
      <ul className="place-ips">
        {p.top.map((t) => (
          <li key={t.ip}>
            <span className="swatch" style={{ background: GROUP_COLORS[t.group] }} />
            <span className="grow">
              <button className="linklike mono" onClick={() => onIp(t.ip)}>{t.ip}</button>
              <span className="small block">{t.who ? `${t.who} · ` : ""}{t.label}</span>
              {t.org && <span className="muted small block">{t.org}</span>}
            </span>
            <span className="muted small nowrap">{fmtNum(t.count)}×</span>
          </li>
        ))}
      </ul>
      {p.ips > p.top.length && <p className="muted small">… und {p.ips - p.top.length} weitere</p>}
    </div>
  );
}

export function WhyView({ range, host, onIp }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [cat, setCat] = useState("");
  const [limit, setLimit] = useState(25);

  useEffect(() => {
    let alive = true;
    setData(null); setError("");
    api.get(`/access/visitors${qs({ range, host })}`).then((d) => alive && setData(d)).catch((e) => alive && setError(e.message));
    return () => { alive = false; };
  }, [range, host]);

  if (error) return <p className="error" role="alert">{error}</p>;
  if (!data) return <Loading rows={3} />;
  if (!data.items.length) return <EmptyState title="Keine Zugriffe in diesem Zeitraum" text="Sobald der Agent Zugriffe meldet, steht hier, wer sie verursacht und warum." />;

  const total = data.categories.reduce((s, c) => s + c.count, 0);
  const byGroup = GROUP_ORDER.map((g) => ({ g, cats: data.categories.filter((c) => c.group === g) })).filter((x) => x.cats.length);
  const items = cat ? data.items.filter((i) => i.category === cat) : data.items;
  const current = data.categories.find((c) => c.category === cat);

  return (
    <>
      <div className="why-share" aria-label="Anteile nach Gruppe">
        {byGroup.map(({ g, cats }) => {
          const n = cats.reduce((s, c) => s + c.count, 0);
          return <span key={g} style={{ flexGrow: n, background: GROUP_COLORS[g] }} title={`${data.groups[g]}: ${fmtNum(n)}`} />;
        })}
      </div>
      <div className="why-groups" data-tour="access-why">
        {byGroup.map(({ g, cats }) => {
          const n = cats.reduce((s, c) => s + c.count, 0);
          return (
            <section key={g} className={`panel why-group grp-${g}`}>
              <div className="why-group-head">
                <span className="swatch lg" style={{ background: GROUP_COLORS[g] }} />
                <div>
                  <h2>{data.groups[g]}</h2>
                  <p className="muted small">{GROUP_HINT[g]}</p>
                </div>
                <span className="why-share-num">{fmtNum((n / Math.max(1, total)) * 100, 0)} %</span>
              </div>
              <ul className="why-cats">
                {cats.map((c) => (
                  <li key={c.category}>
                    <button type="button" className={`why-cat ${cat === c.category ? "on" : ""}`} onClick={() => { setCat(cat === c.category ? "" : c.category); setLimit(25); }} aria-pressed={cat === c.category}>
                      <span className="grow">
                        <strong>{c.label}</strong>
                        <span className="muted small block">{c.description}</span>
                        {c.who.length > 0 && <span className="small block who">{c.who.join(", ")}</span>}
                      </span>
                      <span className="why-num"><strong>{fmtNum(c.count)}</strong><span className="muted small block">{fmtNum(c.ips)} {c.ips === 1 ? "Adresse" : "Adressen"}</span></span>
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          );
        })}
      </div>

      <section className="panel">
        <div className="panel-head">
          <h2>{current ? current.label : "Alle Adressen"} <span className="muted small">mit Begründung</span></h2>
          {cat && <button className="chip on" onClick={() => setCat("")}>{current?.label} ✕</button>}
        </div>
        <div className="table-wrap flat">
          <table className="rows why-table">
            <thead><tr><th><Term k="ip">IP-Adresse</Term></th><th>Wer und warum</th><th className="hide-sm">Netz</th><th className="num">Zugriffe</th></tr></thead>
            <tbody>
              {items.slice(0, limit).map((i) => (
                <tr key={i.ip}>
                  <td className="nowrap">{(i.country || i.category === "home") && <><Country code={i.country} org={i.category === "home" ? "Heimnetz" : i.as_org} compact /> </>}<button className="linklike mono" onClick={() => onIp(i.ip)}>{i.ip}</button>
                    <span className="muted small block">{fmtAgo(i.last)}</span></td>
                  <td>
                    <span className="why-label"><span className="swatch" style={{ background: GROUP_COLORS[i.group] }} />{i.who && i.who !== i.label ? <><strong>{i.who}</strong> · </> : null}{i.label}</span>
                    <span className="muted small block">{i.why.join(" · ")}</span>
                  </td>
                  <td className="hide-sm muted small">{i.as_org || "–"}</td>
                  <td className="num">{fmtNum(i.count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {items.length > limit && <div className="actions"><button className="btn" onClick={() => setLimit((l) => l + 50)}>Weitere zeigen ({fmtNum(items.length - limit)})</button></div>}
        <p className="muted small">Die Zuordnung beruht auf Programmname (User-Agent), Netzbetreiber, aufgerufenen Pfaden und erkannten Vorfällen. Programmnamen kann jeder frei wählen; deshalb wird z. B. ein „Googlebot“ aus einem fremden Rechenzentrum als verdächtig markiert.</p>
      </section>
    </>
  );
}

export function ReasonBox({ reason }) {
  if (!reason) return null;
  return (
    <div className={`reason-box grp-${reason.group}`}>
      <span className="swatch lg" style={{ background: GROUP_COLORS[reason.group] }} />
      <div>
        <div className="muted small">Warum greift diese Adresse zu?</div>
        <strong>{reason.who && reason.who !== reason.label ? `${reason.who}: ` : ""}{reason.label}</strong>
        <p className="small">{reason.description}</p>
        {reason.why?.length > 0 && <ul className="plain-list small muted">{reason.why.map((w) => <li key={w}>{w}</li>)}</ul>}
      </div>
    </div>
  );
}
