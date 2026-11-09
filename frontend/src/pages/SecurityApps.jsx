import { useCallback, useEffect, useState } from "react";
import { api, fmtAgo } from "../api.js";
import { Loading, toast } from "../components/feedback.jsx";
import { EmptyState, Pill } from "../components/ui.jsx";
import { InfoTip } from "../components/help.jsx";

const STATUS = {
  vulnerable: ["Sicherheitslücke!", "due", 0],
  major: ["Hauptversion zurück", "soon", 1],
  minor: ["Update verfügbar", "soon", 2],
  patch: ["Kleines Update", "soon", 3],
  unknown: ["Version unbekannt", "muted", 4],
  current: ["Aktuell", "ok", 5],
};

const SEC = { success: ["keine bekannten Lücken", "ok"], failure: ["Lücke ohne automatische Korrektur", "due"], none: ["Prüfung nicht eingerichtet", "muted"] };

function OwnRepos({ items }) {
  if (!items?.length) return null;
  return (
    <section className="panel">
      <h2>Deine eigenen Apps (GitHub)</h2>
      <p className="muted small">Pakete prüft GitHub jeden Tag, kleine Sicherheitskorrekturen übernimmt Dependabot selbst. Auf deinen Server kommen sie mit dem Update-Knopf der jeweiligen App, die dich per Push erinnert.</p>
      <ul className="plain-list own-repos">
        {items.map((r) => {
          const [text, tone] = SEC[r.security] || [r.security || "unbekannt", "muted"];
          return (
            <li key={r.repo}>
              <span className="grow"><a href={r.url} target="_blank" rel="noreferrer noopener"><strong>{r.repo.split("/")[1]}</strong></a>
                <span className="muted small block">
                  {r.error ? r.error : <>Sicherheitsprüfung {r.security_at ? fmtAgo(r.security_at) : ""}{r.dependabot_open ? ` · ${r.dependabot_open} offene Dependabot-Vorschläge` : ""}</>}
                </span></span>
              {r.security_url ? <a href={r.security_url} target="_blank" rel="noreferrer noopener"><Pill tone={tone}>{text}</Pill></a> : <Pill tone={tone}>{text}</Pill>}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

export default function Apps({ isAdmin }) {
  const [d, setD] = useState(null);
  const [open, setOpen] = useState(null);
  const load = useCallback(() => api.get("/security/apps").then(setD).catch((e) => toast(e.message, "error")), []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!d?.running) return undefined;
    const id = setInterval(load, 4000);
    return () => clearInterval(id);
  }, [d?.running, load]);
  async function check() {
    try { await api.post("/security/apps/check", {}); setD((x) => ({ ...x, running: true })); toast("Prüfung gestartet."); } catch (e) { toast(e.message, "error"); }
  }
  if (!d) return <Loading rows={2} />;

  const apps = d.items.filter((i) => i.app).sort((a, b) => (STATUS[a.status]?.[2] ?? 9) - (STATUS[b.status]?.[2] ?? 9));
  const other = d.items.filter((i) => !i.app);
  const vuln = apps.filter((a) => a.status === "vulnerable");
  const behind = apps.filter((a) => ["major", "minor", "patch"].includes(a.status));
  const tone = !d.checked ? "info" : vuln.length ? "crit" : behind.length ? "warn" : "ok";

  return (
    <>
      <section className={`panel verdict verdict-${tone}`}>
        <div className="panel-head">
          <div>
            <h2>{!d.checked ? "Noch nicht geprüft" : vuln.length ? `${vuln.length === 1 ? "Eine App hat" : `${vuln.length} Apps haben`} bekannte Sicherheitslücken`
              : behind.length ? `${behind.length === 1 ? "Für eine App gibt" : `Für ${behind.length} Apps gibt`} es Updates` : "Alle erkannten Apps sind aktuell"}
              {" "}<InfoTip k="app_versions" /></h2>
            <p className="muted">{d.checked ? <>Zuletzt geprüft: {fmtAgo(d.checked)} · </> : null}
              Veraltete Apps sind der häufigste Weg, wie Heimserver tatsächlich übernommen werden. NetworkHelper liest die Version deiner Apps ab (aus den Containern, die die Agenten melden, und über deine Domains) und vergleicht sie mit der neuesten Version und mit veröffentlichten Sicherheitswarnungen.
              {" "}<strong>Eine Push-Nachricht kommt nur, wenn deine Version eine bekannte Lücke hat und es ein Update gibt.</strong> NetworkHelper ändert dabei nichts selbst.</p>
          </div>
          {isAdmin && <button className="btn primary" onClick={check} disabled={d.running}>{d.running ? "Prüfe …" : "Jetzt prüfen"}</button>}
        </div>
      </section>

      {d.checked && apps.length === 0 ? (
        <EmptyState title="Keine bekannte App erkannt" text={`Erkannt werden zurzeit: ${d.known_apps.join(", ")}. Container werden über die Agenten erkannt.`} />
      ) : (
        <section className="panel">
          <h2>Deine Apps</h2>
          <ul className="app-list">
            {apps.map((a) => {
              const [text, pill] = STATUS[a.status] || [a.status, "muted"];
              const key = a.host + a.app;
              return (
                <li key={key} className={`app-row st-${a.status}`}>
                  <button className="app-head" onClick={() => setOpen(open === key ? null : key)} aria-expanded={open === key}>
                    <span className="grow">
                      <strong>{a.name}</strong> <span className="muted small">{a.host}</span>
                      {a.image && <span className="muted small mono block">{a.image}</span>}
                      <span className="small block">
                        {a.version ? <>Installiert: <span className="mono">{a.version}</span></> : a.source === "container" ? "Version nicht ablesbar (Image ohne Versionsangabe, z. B. Tag „latest“)" : "Version ohne Anmeldung nicht ablesbar"}
                        {a.latest && <> · Neueste: <span className="mono">{a.latest.replace(/^v/, "")}</span></>}
                      </span>
                    </span>
                    <Pill tone={pill}>{text}</Pill>
                  </button>
                  {open === key && (
                    <div className="app-detail">
                      {a.advisories?.length > 0 && (
                        <>
                          <h3 className="sub-title">Bekannte Sicherheitslücken in deiner Version</h3>
                          <ul className="plain-list small">
                            {a.advisories.map((x) => (
                              <li key={x.id}>
                                <Pill tone={["critical", "high"].includes(x.severity) ? "due" : "soon"}>{{ critical: "kritisch", high: "hoch", moderate: "mittel", medium: "mittel", low: "niedrig" }[x.severity] || x.severity}</Pill>
                                {" "}<a href={x.url} target="_blank" rel="noreferrer noopener">{x.summary}</a>
                                <span className="muted block">{x.cve ? `${x.cve} · ` : ""}behoben in {x.patched || "neuerer Version"}</span>
                              </li>
                            ))}
                          </ul>
                        </>
                      )}
                      <p className="small"><strong>So aktualisierst du:</strong> {a.hint}</p>
                      {a.release_url && <p className="small"><a href={a.release_url} target="_blank" rel="noreferrer noopener">Was ist neu in {a.latest}?</a></p>}
                      {a.status === "major" && !a.advisories?.length && <p className="small muted">Eine Hauptversion zurück ist nicht automatisch unsicher: Viele Projekte pflegen ältere Hauptversionen noch eine Weile mit Sicherheitsupdates. Plane das Update trotzdem ein.</p>}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
          {other.length > 0 && (
            <p className="muted small">Ohne erkannte App: {other.map((o) => o.host + (o.error ? ` (${o.error})` : "")).join(", ")}. Erkannt werden zurzeit {d.known_apps.join(", ")}.</p>
          )}
        </section>
      )}
      <OwnRepos items={d.own} />
    </>
  );
}
