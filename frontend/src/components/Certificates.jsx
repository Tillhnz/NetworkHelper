import { useCallback, useEffect, useState } from "react";
import { api, fmtAgo, fmtDateTime } from "../api.js";
import { Loading, toast } from "./feedback.jsx";
import { Pill } from "./ui.jsx";
import { InfoTip } from "./help.jsx";

function DaysPill({ c }) {
  if (c.days_left == null) return <Pill tone="muted">unbekannt</Pill>;
  if (c.days_left < 0) return <Pill tone="due">abgelaufen</Pill>;
  if (c.days_left < 14) return <Pill tone="due">noch {c.days_left} Tage</Pill>;
  if (c.days_left < 30) return <Pill tone="soon">noch {c.days_left} Tage</Pill>;
  return <Pill tone="ok">noch {c.days_left} Tage</Pill>;
}

/** Zertifikate aus dem Proxy Manager mit Erneuern-Knopf. */
export default function Certificates({ isAdmin }) {
  const [d, setD] = useState(null);
  const load = useCallback(() => api.get("/security/certificates").then(setD).catch((e) => toast(e.message, "error")), []);
  useEffect(() => { load(); }, [load]);
  const running = d?.items?.some((c) => c.running);
  useEffect(() => {
    if (!running) return undefined;
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [running, load]);

  async function renew(c) {
    try {
      await api.post(`/security/certificates/${c.id}/renew`, {});
      toast("Erneuerung gestartet. Let's Encrypt braucht dafür bis zu zwei Minuten.");
      setD((x) => ({ ...x, items: x.items.map((i) => (i.id === c.id ? { ...i, running: true } : i)) }));
    } catch (e) { toast(e.message, "error"); }
  }
  if (!d) return <Loading rows={2} />;
  if (!d.configured) return null;

  return (
    <section className="panel">
      <h2>Zertifikate im Proxy Manager <InfoTip k="cert_renew" /></h2>
      <p className="muted small">
        {d.auto ? <>NetworkHelper erneuert Let's-Encrypt-Zertifikate selbst, sobald sie in weniger als {d.auto_days} Tagen ablaufen, und sagt dir, warum es nicht klappt.</>
          : "Die automatische Erneuerung durch NetworkHelper ist unter Administration → Proxy Manager ausgeschaltet. Der Proxy Manager versucht es trotzdem selbst."}
      </p>
      {d.error && <p className="error">{d.error}</p>}
      <ul className="plain-list cert-list">
        {d.items.map((c) => (
          <li key={c.id} className="cert-row">
            <div className="cert-head">
              <span className="grow"><strong>{c.name}</strong>
                <span className="muted small block">
                  {c.provider === "letsencrypt" ? "Let's Encrypt" : "Eigenes Zertifikat"}{c.dns_challenge && " · DNS-Bestätigung"}
                  {c.expires_on && <> · gültig bis {fmtDateTime(c.expires_on)}</>}
                  {c.used_by.length > 0 ? <> · für {c.used_by.join(", ")}</> : " · von keinem Proxy Host genutzt"}
                </span></span>
              <DaysPill c={c} />
              {isAdmin && c.renewable && <button className="btn small" onClick={() => renew(c)} disabled={c.running}>{c.running ? "Erneuere …" : "Jetzt erneuern"}</button>}
            </div>
            {c.last && !c.running && (c.last.ok ? (
              <p className="small muted">Zuletzt {c.last.auto ? "automatisch " : ""}erneuert {fmtAgo(c.last.at)}.</p>
            ) : (
              <div className="cert-error">
                <p className="small"><strong>Erneuerung {fmtAgo(c.last.at)} fehlgeschlagen:</strong> {c.last.why}</p>
                <p className="small"><strong>So behebst du es:</strong> {c.last.fix}</p>
                {c.last.error && <details className="small"><summary>Originalmeldung</summary><pre className="code-block">{c.last.error}</pre></details>}
              </div>
            ))}
          </li>
        ))}
      </ul>
    </section>
  );
}
