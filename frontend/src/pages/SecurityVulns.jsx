import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, fmtAgo, fmtNum } from "../api.js";
import { confirmDialog, Loading, toast } from "../components/feedback.jsx";
import { EmptyState, Pill } from "../components/ui.jsx";
import { InfoTip } from "../components/help.jsx";

const SEV_TONE = { kritisch: "due", hoch: "due", mittel: "soon", niedrig: "muted", unbekannt: "muted" };

function Finding({ f, isAdmin, reload }) {
  async function accept(value) {
    try { await api.put(`/security/vulns/findings/${f.id}`, { accepted: value }); reload(); } catch (e) { toast(e.message, "error"); }
  }
  return (
    <li className={`vuln ${f.accepted ? "acked" : ""}`}>
      <div className="vuln-head">
        <Pill tone={SEV_TONE[f.severity]}>{f.severity}{f.score != null && ` ${fmtNum(f.score, 1)}`}</Pill>
        {f.kev && <Pill tone="due">wird ausgenutzt</Pill>}
        <span className="grow"><strong>{f.package}</strong> <span className="mono small">{f.version}</span> <span className="muted small">· {f.language}</span></span>
        {f.accepted && <Pill tone="muted">hingenommen</Pill>}
      </div>
      <p className="small">{f.summary || f.vuln}</p>
      <p className="small muted">
        {f.fixed ? <>Behoben in <span className="mono">{f.fixed}</span></> : "Noch kein Update verfügbar"}
        {" · "}<a href={f.url} target="_blank" rel="noreferrer noopener">{f.cves[0] || f.vuln}</a>
        {" · "}bekannt seit {fmtAgo(f.first_seen)}
        {isAdmin && <> · <button className="link small" onClick={() => accept(!f.accepted)}>{f.accepted ? "Wieder melden" : "Risiko hinnehmen"}</button></>}
      </p>
    </li>
  );
}

const ACTION = {
  queued: ["wartet auf den Agenten", "muted"], sent: ["an den Agenten geschickt", "muted"], running: ["läuft …", "soon"],
  ok: ["erfolgreich", "ok"], no_update: ["kein Update verfügbar", "soon"], rolled_back: ["zurückgenommen", "due"],
  failed: ["fehlgeschlagen", "due"], manual: ["nur von Hand", "soon"],
};

function Remedy({ t, isAdmin, reload }) {
  const r = t.remedy;
  const busy = t.actions.some((a) => ["queued", "sent", "running"].includes(a.status));
  async function fix() {
    try { await api.post(`/security/vulns/targets/${t.id}/fix`, {}); toast("Update angestoßen. Der Agent meldet sich in etwa einer Minute."); reload(); } catch (e) { toast(e.message, "error"); }
  }
  async function copy(cmd) {
    try { await navigator.clipboard.writeText(cmd); toast("Befehl kopiert."); } catch { toast("Kopieren nicht möglich, bitte markieren.", "error"); }
  }
  return (
    <div className="remedy">
      <h3 className="sub-title">So schließt du die Lücken</h3>
      {isAdmin && r.action && (
        r.agent_allows
          ? <p><button className="btn primary small" onClick={fix} disabled={busy}>{busy ? "Update läuft …" : "Jetzt automatisch aktualisieren"}</button> <span className="muted small">{r.action.label}. Startet der Dienst danach nicht sauber, kehrt der Agent zur alten Version zurück.</span></p>
          : <p className="small muted">Ein Klick genügt, wenn der Agent Updates ausführen darf: auf diesem Server den Installationsbefehl mit <span className="mono">--allow-updates</span> erneut ausführen.</p>
      )}
      <ol className="small steps-list">
        {r.steps.map((s, i) => (
          <li key={i}>{s.text}{s.cmd && <div className="cmd"><code>{s.cmd}</code><button className="link small" onClick={() => copy(s.cmd)}>Kopieren</button></div>}</li>
        ))}
      </ol>
      {r.no_fix && <p className="small muted">{r.no_fix} Hier hilft nur abwarten, die Sperre lassen oder das Risiko bewusst hinnehmen.</p>}
      {t.actions.length > 0 && (
        <ul className="plain-list small actions">
          {t.actions.map((a) => {
            const [txt, tone] = ACTION[a.status] || [a.status, "muted"];
            return (
              <li key={a.id}><span className="grow">{a.label} <span className="muted">· {a.auto ? "automatisch" : a.by} · {fmtAgo(a.created_at)}</span>
                {a.log && <details><summary>Protokoll</summary><pre className="code-block">{a.log}</pre></details>}</span>
                <Pill tone={tone}>{txt}</Pill></li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function Target({ t, isAdmin, reload, quarantined }) {
  const [open, setOpen] = useState(false);
  const [all, setAll] = useState(null);
  const active = t.findings.filter((f) => !f.accepted);
  const serious = active.filter((f) => f.kev || (f.score || 0) >= 7);
  const shown = all || t.findings;
  async function loadAll() {
    try { setAll(await api.get(`/security/vulns/targets/${t.id}/findings`)); } catch (e) { toast(e.message, "error"); }
  }
  const tone = serious.some((f) => f.kev || f.score >= 9) ? "due" : serious.length ? "soon" : "ok";
  async function lock(s) {
    if (!(await confirmDialog(`${s.domains[0]} ist danach nur noch aus dem Heimnetz erreichbar, bis du die Sperre aufhebst.`, { title: "Vorsichtshalber sperren?", confirmLabel: "Sperren" }))) return;
    try { await api.post("/security/vulns/quarantine", { host_id: s.id }); toast("Gesperrt: nur noch aus dem Heimnetz erreichbar."); reload(); } catch (e) { toast(e.message, "error"); }
  }
  return (
    <li className="vuln-target">
      <button className="pve-row" onClick={() => setOpen(!open)} aria-expanded={open}>
        <span className="grow">
          <strong>{t.label}</strong> <span className="muted small">{t.agent}{t.image && ` · ${t.image}`}</span>
          <span className="small block">
            {t.services.length ? t.services.map((s) => (
              <span key={s.id} className="svc">{s.domains[0]}{quarantined.has(s.id) ? " 🔒" : s.protected ? " (Zugriffsliste)" : ""}</span>
            )) : <span className="muted">keine Domain zeigt hierher</span>}
          </span>
          <span className="muted small block">{fmtNum(t.packages)} Pakete{t.distro && ` · ${t.distro}`} · Inventur {fmtAgo(t.scanned_at)}{t.error && ` · ${t.error}`}</span>
        </span>
        {serious.length ? <Pill tone={tone}>{serious.length} {serious.length === 1 ? "Lücke" : "Lücken"}</Pill>
          : t.minor ? <Pill tone="muted">{t.minor} gering</Pill> : <Pill tone="ok">sauber</Pill>}
      </button>
      {open && (
        <div className="pve-detail">
          {shown.length > 0 ? <ul className="plain-list">{shown.map((f) => <Finding key={f.id} f={f} isAdmin={isAdmin} reload={reload} />)}</ul>
            : <p className="small muted">Keine schweren Lücken.</p>}
          {t.minor > 0 && !all && (
            <button className="link small" onClick={loadAll}>{t.minor} weitere mit geringer oder unbekannter Schwere zeigen</button>
          )}
          {t.remedy && (active.length > 0 || t.minor > 0) && <Remedy t={t} isAdmin={isAdmin} reload={reload} />}
          {isAdmin && t.services.filter((s) => !quarantined.has(s.id)).map((s) => (
            <button key={s.id} className="btn small" onClick={() => lock(s)}>{s.domains[0]} vorsichtshalber sperren</button>
          ))}
        </div>
      )}
    </li>
  );
}

export default function Vulns({ isAdmin }) {
  const [d, setD] = useState(null);
  const load = useCallback(() => api.get("/security/vulns").then(setD).catch((e) => toast(e.message, "error")), []);
  useEffect(() => { load(); }, [load]);
  const actionBusy = d?.items?.some((t) => t.actions?.some((a) => ["queued", "sent", "running"].includes(a.status)));
  useEffect(() => {
    if (!d?.running && !actionBusy) return undefined;
    const id = setInterval(load, d?.running ? 3000 : 8000);
    return () => clearInterval(id);
  }, [d?.running, actionBusy, load]);

  async function check() {
    try { await api.post("/security/vulns/check", {}); setD((x) => ({ ...x, running: true })); } catch (e) { toast(e.message, "error"); }
  }
  async function release(q) {
    if (!(await confirmDialog(`${q.domains} ist danach wieder aus dem Internet erreichbar. Die Lücke ist noch nicht behoben, wenn du nicht aktualisiert hast.`, { title: "Sperre aufheben?", confirmLabel: "Freigeben" }))) return;
    try { await api.post(`/security/vulns/quarantine/${q.id}/release`, {}); toast("Wieder erreichbar."); load(); } catch (e) { toast(e.message, "error"); }
  }

  if (!d) return <Loading rows={3} />;
  const active = d.quarantines.filter((q) => !q.released_at && !q.error);
  const quarantined = new Set(active.map((q) => q.host_id));
  const serious = d.items.flatMap((t) => t.findings.filter((f) => !f.accepted && (f.kev || (f.score || 0) >= 7)));
  const exposedSerious = d.items.filter((t) => t.exposed).flatMap((t) => t.findings.filter((f) => !f.accepted && (f.kev || (f.score || 0) >= 7)));
  const tone = !d.items.length ? "info" : active.length || exposedSerious.some((f) => f.kev || f.score >= 9) ? "crit" : serious.length ? "warn" : "ok";

  return (
    <>
      <section className={`panel verdict verdict-${tone}`}>
        <div className="panel-head">
          <div>
            <h2>
              {!d.items.length ? "Noch keine Inventur"
                : active.length ? `${active.length === 1 ? "Ein Dienst ist" : `${active.length} Dienste sind`} wegen einer Lücke gesperrt`
                  : exposedSerious.length ? `${exposedSerious.length} schwere ${exposedSerious.length === 1 ? "Lücke" : "Lücken"} in Diensten, die im Internet stehen`
                    : serious.length ? "Schwere Lücken nur in internen Diensten" : "Keine schweren Lücken bekannt"}
              {" "}<InfoTip k="vulns" />
            </h2>
            <p className="muted">
              {d.last_scan ? <>Zuletzt abgeglichen {fmtAgo(d.last_scan.at)} · {fmtNum(d.items.length)} Container und Server. </> : null}
              {d.auto ? <>Bei kritischen Lücken (ab CVSS {d.threshold}) oder bereits ausgenutzten Lücken wird ein Dienst im Internet automatisch gesperrt. </> : "Automatisches Sperren ist aus. "}
              {d.push ? "Push ist eingerichtet." : <><strong>Push ist noch nicht eingerichtet</strong> (Administration → E-Mail & Push).</>}
            </p>
            {d.error && <p className="error small">{d.error.error}</p>}
            {d.npm_error && <p className="error small">Proxy Manager: {d.npm_error}</p>}
          </div>
          {isAdmin && d.items.length > 0 && <button className="btn primary" onClick={check} disabled={d.running}>{d.running ? "Prüfe …" : "Jetzt prüfen"}</button>}
        </div>
      </section>

      {active.length > 0 && (
        <section className="panel">
          <h2>Gesperrt: nur noch aus dem Heimnetz erreichbar</h2>
          <ul className="plain-list">
            {active.map((q) => (
              <li key={q.id} className="quarantine">
                <span className="grow"><strong>{q.domains}</strong> <span className="muted small">seit {fmtAgo(q.started_at)}{q.auto ? " · automatisch" : " · von Hand"}</span>
                  <span className="small block pre-line">{q.reason}</span></span>
                {isAdmin && <button className="btn small" onClick={() => release(q)}>Freigeben</button>}
              </li>
            ))}
          </ul>
          <p className="muted small">Aktualisiere den Dienst (z. B. <span className="mono">docker compose pull && docker compose up -d</span>). Meldet der Agent die neue Version, gibt NetworkHelper ihn von selbst frei.</p>
        </section>
      )}

      {!d.items.length ? (
        <EmptyState title="Die Agenten haben noch nichts gemeldet"
          text="Ab Agent-Version 1.3 meldet jeder Agent einmal am Tag und bei jedem neuen Container, welche Pakete installiert sind. Ältere Agenten aktualisieren sich von selbst; danach dauert die erste Inventur einige Minuten.">
          {isAdmin && <Link className="btn" to="/connections">Zu den Agenten</Link>}
        </EmptyState>
      ) : (
        <section className="panel">
          <h2>Container und Server</h2>
          <ul className="plain-list pve-guests">
            {d.items.map((t) => <Target key={t.id} t={t} isAdmin={isAdmin} reload={load} quarantined={quarantined} />)}
          </ul>
        </section>
      )}

      {d.unmapped.length > 0 && (
        <section className="panel">
          <h2>Dienste ohne Inventur</h2>
          <p className="muted small">Für diese Domains weiß NetworkHelper nicht, was dahinter läuft. Installiere den Agenten auf dem Server, auf den sie zeigen.</p>
          <ul className="plain-list small">{d.unmapped.map((u) => <li key={u.id}><span className="grow">{u.domains.join(", ")}</span><span className="mono muted">→ {u.forward}</span></li>)}</ul>
        </section>
      )}

      {d.quarantines.some((q) => q.released_at || q.error) && (
        <section className="panel">
          <h2>Frühere Sperren</h2>
          <ul className="plain-list small">
            {d.quarantines.filter((q) => q.released_at || q.error).slice(0, 15).map((q) => (
              <li key={q.id}><span className="grow">{q.domains} <span className="muted">· {fmtAgo(q.started_at)}</span></span>
                <span className="muted">{q.error ? `fehlgeschlagen: ${q.error}` : `freigegeben ${fmtAgo(q.released_at)} (${q.released_by})`}</span></li>
            ))}
          </ul>
        </section>
      )}
    </>
  );
}
