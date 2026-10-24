import { useCallback, useEffect, useState } from "react";
import { api, fmtAgo, fmtNum } from "../api.js";
import { Loading, toast } from "../components/feedback.jsx";
import { EmptyState, Pill } from "../components/ui.jsx";
import { InfoTip } from "../components/help.jsx";

const RESULT = {
  exposed: ["Lesbar!", "due"],
  unclear: ["Unklar, bitte ansehen", "soon"],
  catchall: ["Harmlos: normale Seite", "ok"],
  protected: ["Gesperrt (401/403)", "ok"],
  missing: ["Nicht vorhanden", "ok"],
  redirect: ["Umleitung", "ok"],
  error: ["Keine Antwort", "muted"],
};

function ResultPill({ r }) {
  if (!r) return <Pill tone="muted">noch nicht geprüft</Pill>;
  const [text, tone] = RESULT[r] || [r, "muted"];
  return <Pill tone={tone}>{text}</Pill>;
}

export default function Exposure({ isAdmin }) {
  const [d, setD] = useState(null);
  const [showAll, setShowAll] = useState(false);
  const load = useCallback(() => api.get("/security/exposure").then(setD).catch((e) => toast(e.message, "error")), []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!d?.running) return undefined;
    const id = setInterval(load, 4000);
    return () => clearInterval(id);
  }, [d?.running, load]);

  async function check() {
    try { await api.post("/security/exposure/check", {}); setD((x) => ({ ...x, running: true })); toast("Prüfung gestartet. Das dauert pro Seite etwa eine halbe Minute."); } catch (e) { toast(e.message, "error"); }
  }
  async function ack(f, value) {
    try { await api.put(`/security/exposure/${f.id}`, { acknowledged: value }); load(); } catch (e) { toast(e.message, "error"); }
  }
  if (!d) return <Loading rows={3} />;

  const open = d.findings.filter((f) => !f.fixed_at);
  const exposed = open.filter((f) => f.result === "exposed" && !f.acknowledged);
  const crit = exposed.filter((f) => f.severity === "crit");
  const unclear = open.filter((f) => f.result === "unclear" && !f.acknowledged);
  const fixed = d.findings.filter((f) => f.fixed_at);
  const hits = showAll ? d.log_hits : d.log_hits.slice(0, 12);
  const hitsHarmless = d.log_hits.filter((h) => ["catchall", "protected", "missing", "redirect"].includes(h.result)).length;
  const tone = !d.last ? "info" : crit.length ? "crit" : exposed.length || unclear.length ? "warn" : "ok";

  return (
    <>
      <section className={`panel verdict verdict-${tone}`}>
        <div className="panel-head">
          <div>
            <h2>
              {!d.last ? "Noch nicht geprüft"
                : crit.length ? `${crit.length === 1 ? "Ein Geheimnis ist" : `${crit.length} Geheimnisse sind`} von außen lesbar`
                  : exposed.length ? "Etwas ist öffentlich, das es nicht sein sollte"
                    : unclear.length ? "Fast alles in Ordnung, eine Sache bitte ansehen"
                      : "Keiner der geprüften Angriffswege funktioniert"}
            </h2>
            <p className="muted">
              {d.last
                ? <>Zuletzt geprüft: {fmtAgo(d.last.finished)} · {fmtNum(d.hosts.length)} {d.hosts.length === 1 ? "Seite" : "Seiten"}, je {fmtNum(d.last.probes)} typische Angriffsziele
                  {d.log_hits.length > 0 && <> und {fmtNum(d.log_hits.length)} Adressen, die Angreifer bei dir erfolgreich aufgerufen haben</>}.</>
                : "NetworkHelper ruft bei deinen eigenen Seiten die Adressen auf, die Angreifer typischerweise ausprobieren, und schaut, ob dort wirklich etwas Geheimes steht."}
              {!d.enabled && " Die regelmäßige Prüfung ist unter Administration → Sicherheit ausgeschaltet."}
            </p>
          </div>
          {isAdmin && <button className="btn primary" onClick={check} disabled={d.running}>{d.running ? "Prüfe …" : "Jetzt prüfen"}</button>}
        </div>
      </section>

      {open.length > 0 && (
        <section className="panel">
          <h2>Gefunden</h2>
          <ul className="exposure-list">
            {open.map((f) => (
              <li key={f.id} className={`exposure sev-${f.result === "exposed" ? f.severity : "info"} ${f.acknowledged ? "acked" : ""}`}>
                <div className="exposure-head">
                  <ResultPill r={f.result} />
                  <strong className="grow">{f.label}</strong>
                  {f.acknowledged && <Pill tone="muted">bewusst so</Pill>}
                </div>
                <a className="mono small exposure-url" href={`https://${f.host}${f.path}`} target="_blank" rel="noreferrer noopener">{f.host}{f.path}</a>
                {f.evidence && <p className="small">Gefunden: <span className="mono">{f.evidence}</span></p>}
                {f.attacked > 0 ? (
                  <p className="small tone-crit"><strong>Laut Protokoll {fmtNum(f.attacked)}× erfolgreich von {fmtNum(f.attacker_ips)} fremden {f.attacker_ips === 1 ? "Adresse" : "Adressen"} abgerufen.</strong> Gehe davon aus, dass die Inhalte bekannt sind, und ändere alle Passwörter und Schlüssel darin.</p>
                ) : f.result === "exposed" && <p className="small muted">Im Protokoll (letzte 30 Tage) hat noch kein Fremder diese Adresse erfolgreich abgerufen.</p>}
                <p className="small"><strong>So behebst du es:</strong> {f.fix}</p>
                <p className="small muted">Zuerst gesehen: {fmtAgo(f.first_seen)} · Nach dem Beheben „Jetzt prüfen“ drücken, dann verschwindet der Eintrag.</p>
                {isAdmin && f.severity !== "crit" && (
                  <button className="link small" onClick={() => ack(f, !f.acknowledged)}>{f.acknowledged ? "Doch wieder melden" : "Ist bewusst so (z. B. nur mit Passwort)"}</button>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="panel">
        <div className="panel-head">
          <h2>Angriffe, auf die deine Seiten mit „OK“ geantwortet haben <InfoTip k="attack_hit" /></h2>
        </div>
        {d.log_hits.length === 0 ? (
          <p className="muted">In den letzten 30 Tagen hat keine typische Angriffs-Anfrage (/.env, /.git, /wp-login.php …) eine erfolgreiche Antwort bekommen. Alle wurden abgewiesen oder liefen ins Leere.</p>
        ) : (
          <>
            <p className="muted small">
              Ein „200 OK“ heißt noch nicht, dass der Angriff geklappt hat: Viele Apps zeigen für jede unbekannte Adresse einfach ihre Startseite.
              NetworkHelper ruft jede dieser Adressen deshalb selbst auf und schaut in den Inhalt.
              {hitsHarmless > 0 && <> {fmtNum(hitsHarmless)} von {fmtNum(d.log_hits.length)} haben sich so als harmlos herausgestellt.</>}
            </p>
            <div className="table-wrap flat">
              <table className="rows hits-table">
                <thead><tr><th>Adresse</th><th>Prüfergebnis</th></tr></thead>
                <tbody>
                  {hits.map((h) => (
                    <tr key={h.host + h.path}>
                      <td className="hit-url"><span className="mono small">{h.host}<strong>{h.path}</strong></span>
                        <span className="muted small block">{fmtNum(h.count)}× von {fmtNum(h.ips)} {h.ips === 1 ? "Adresse" : "Adressen"}, zuletzt {fmtAgo(h.last)}</span></td>
                      <td><ResultPill r={h.result} />{h.detail && <span className="muted small block">{h.detail}</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {d.log_hits.length > 12 && <button className="link small" onClick={() => setShowAll(!showAll)}>{showAll ? "Weniger" : `Alle ${d.log_hits.length} zeigen`}</button>}
          </>
        )}
      </section>

      <div className="grid-2">
        <section className="panel">
          <h2>Geprüfte Seiten</h2>
          {d.hosts.length === 0 ? <EmptyState title="Noch keine Seiten" text="Die Liste kommt aus „Zertifikate & Header“. Verbinde den Proxy Manager oder trage dort Hostnamen ein." /> : (
            <ul className="plain-list exposure-hosts">
              {d.hosts.map((h) => (
                <li key={h.host}>
                  <span className="grow"><strong>{h.host}</strong>
                    <span className="muted small block">
                      {h.error ? h.error : <>{fmtNum((h.counts.missing || 0) + (h.counts.protected || 0) + (h.counts.redirect || 0) + (h.counts.catchall || 0))} von {fmtNum(Object.values(h.counts).reduce((a, b) => a + b, 0))} Angriffszielen ohne Treffer
                        {h.catchall && " · zeigt für unbekannte Adressen die Startseite"}</>}
                    </span></span>
                  {h.counts.exposed ? <Pill tone="due">{h.counts.exposed} lesbar</Pill> : h.counts.unclear ? <Pill status="warn">unklar</Pill> : !h.error && <Pill tone="ok">sauber</Pill>}
                </li>
              ))}
            </ul>
          )}
          {fixed.length > 0 && (
            <>
              <h3 className="sub-title">Behoben (letzte 30 Tage)</h3>
              <ul className="plain-list small">{fixed.map((f) => <li key={f.id}><span className="mono">{f.host}{f.path}</span> <span className="muted">· {f.label} · behoben {fmtAgo(f.fixed_at)}</span></li>)}</ul>
            </>
          )}
        </section>
        <section className="panel">
          <h2>Was geprüft wird</h2>
          <ul className="plain-list small probe-list">
            {d.probes.map((p) => (
              <li key={p.key}><Pill status={p.severity === "crit" ? "crit" : "warn"}>{p.severity === "crit" ? "kritisch" : "wichtig"}</Pill> {p.label}
                <span className="mono muted block">{p.paths.join("  ")}</span></li>
            ))}
          </ul>
          <h3 className="sub-title">Was diese Prüfung nicht kann</h3>
          <ul className="small muted bullet">
            <li>Sie sieht nur, was über deine Webseiten von außen lesbar ist. Lücken in den Apps selbst (z. B. eine veraltete Nextcloud) erkennt sie nicht. Dafür hilft: Apps aktuell halten.</li>
            <li>Ob jemand schon auf dem Server selbst ist (Proxmox, Container), kann sie nicht beweisen. Das bräuchte eine Überwachung auf dem Host, zum Beispiel neue Benutzer, Anmeldungen und veränderte Dateien.</li>
            <li>Gefundene Inhalte werden nicht gespeichert, nur die Namen der betroffenen Einträge.</li>
          </ul>
        </section>
      </div>
    </>
  );
}
