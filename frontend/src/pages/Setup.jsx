import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api.js";
import { Switch } from "../components/controls.jsx";
import { toast } from "../components/feedback.jsx";
import { Term, useHelp } from "../components/help.jsx";
import HowItWorks from "../components/HowItWorks.jsx";
import { CopyLine, Dot } from "../components/ui.jsx";

const STEPS = [
  { key: "welcome", label: "Willkommen" },
  { key: "agent", label: "Agent" },
  { key: "npm", label: "Proxy Manager" },
  { key: "porkbun", label: "Domain" },
  { key: "email", label: "E-Mail" },
  { key: "done", label: "Fertig" },
];

function useSetupStatus(active) {
  const [st, setSt] = useState(null);
  const load = useCallback(() => api.get("/setup/status").then(setSt).catch(() => {}), []);
  useEffect(() => {
    load();
    if (!active) return undefined;
    const id = setInterval(load, 4000);
    return () => clearInterval(id);
  }, [load, active]);
  return [st, load];
}

/** Felder speichern und anschließend die Verbindung testen. */
function useSaveAndTest() {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  async function run(values, testPath, describe) {
    setBusy(true);
    setResult(null);
    try {
      const clean = Object.fromEntries(Object.entries(values).filter(([, v]) => v !== ""));
      if (Object.keys(clean).length) await api.put("/admin/settings", { values: clean });
      const r = testPath ? await api.post(testPath, {}) : null;
      setResult({ ok: true, text: describe ? describe(r) : "Gespeichert." });
      return true;
    } catch (e) {
      setResult({ ok: false, text: e.message });
      return false;
    } finally {
      setBusy(false);
    }
  }
  return { busy, result, run };
}

function Result({ result }) {
  if (!result) return null;
  return <p className={`setup-result ${result.ok ? "ok" : "error"}`} role="status">{result.ok ? "✓ " : ""}{result.text}</p>;
}

function Welcome() {
  return (
    <>
      <h2>Schön, dass du da bist</h2>
      <p className="lead">
        NetworkHelper behält deinen Server im Blick, damit du es nicht musst. In den nächsten Schritten verbinden wir ihn mit den Teilen deines Setups.
        Jeder Schritt lässt sich überspringen und später unter Administration nachholen.
      </p>
      <div className="feature-cards">
        <div className="feature-card"><span className="feature-icon" aria-hidden="true">◉</span><strong>Sehen, wer zugreift</strong><p>Jeder Aufruf deiner Dienste mit Herkunft, Uhrzeit und Ergebnis.</p></div>
        <div className="feature-card"><span className="feature-icon" aria-hidden="true">⛨</span><strong>Wissen, ob du sicher bist</strong><p>Offene Türen, ablaufende Zertifikate und Angriffsversuche, verständlich erklärt.</p></div>
        <div className="feature-card"><span className="feature-icon" aria-hidden="true">⌘</span><strong>Namen automatisch</strong><p>Neue Dienste bekommen ihren Eintrag bei Porkbun, und die Adresse stimmt auch nach einem IP-Wechsel.</p></div>
      </div>
      <h3 className="sub-title">So hängt alles zusammen</h3>
      <HowItWorks />
    </>
  );
}

function AgentStep({ st }) {
  const [created, setCreated] = useState(null);
  const [server, setServer] = useState(window.location.origin);
  const [enforce, setEnforce] = useState(true);
  const [busy, setBusy] = useState(false);
  async function create() {
    setBusy(true);
    try { setCreated(await api.post("/agents", { name: "Proxy Manager" })); } catch (e) { toast(e.message, "error"); } finally { setBusy(false); }
  }
  const connected = st?.agents.online > 0;
  const withLogs = st?.agents.with_logs > 0;
  return (
    <>
      <h2>Den Agenten installieren</h2>
      <p className="lead">
        Ein <Term k="agent">Agent</Term> ist ein kleines Programm, das im Container mit deinem <Term k="proxy">Nginx Proxy Manager</Term> mitläuft.
        Er liest mit, wer deine Seiten aufruft, und gibt das an NetworkHelper weiter. Ohne ihn bleibt die Seite „Zugriffe“ leer.
      </p>
      {st?.agents.total > 0 && !created && (
        <p className="setup-result ok">{connected ? `✓ Agent verbunden: ${st.agents.names.join(", ")}` : "Ein Agent ist angelegt, meldet sich aber noch nicht."}</p>
      )}
      {!created && !connected && (
        <div className="actions"><button className="btn primary" onClick={create} disabled={busy}>Agent anlegen und Befehl anzeigen</button></div>
      )}
      {created && (
        <>
          <ol className="steps big">
            <li>Öffne Proxmox im Browser, klicke links auf den <Term k="lxc">Container</Term>, in dem der Nginx Proxy Manager läuft, und dann auf <strong>Console</strong>.</li>
            <li>Melde dich als <code>root</code> an, falls gefragt.</li>
            <li>Kopiere den Befehl unten und füge ihn in die Konsole ein (Rechtsklick → Einfügen), dann Enter.</li>
          </ol>
          <label>Adresse von NetworkHelper, wie der Container sie erreicht
            <input value={server} onChange={(e) => setServer(e.target.value.replace(/\/$/, ""))} />
            <span className="hint">Meist passt die vorgeschlagene. Steht hier ein Name, den nur dein Computer kennt, nimm die IP-Adresse von NetworkHelper.</span>
          </label>
          <Switch checked={enforce} onChange={setEnforce}>Angreifer im Proxy Manager aussperren dürfen (empfohlen)</Switch>
          <CopyLine text={`curl -fsSL ${server}/api/agent/files/install.sh | bash -s -- --server ${server} --token ${created.token}${enforce ? " --enforce-blocks" : ""}`} />
        </>
      )}
      {(created || st?.agents.total > 0) && (
        <div className={`wait-box ${connected ? "is-ok" : ""}`}>
          <Dot tone={connected ? "ok" : "warn"} pulse />
          <div>
            {!connected && <><strong>Warte auf den Agenten …</strong><p className="muted small">Sobald der Befehl durchgelaufen ist, erscheint hier ein Haken. Das dauert meist unter einer Minute.</p></>}
            {connected && <><strong>Agent ist verbunden.</strong><p className="muted small">{withLogs ? "Die ersten Zugriffe sind schon angekommen." : "Zugriffe erscheinen, sobald jemand eine deiner Seiten aufruft."}</p></>}
          </div>
        </div>
      )}
    </>
  );
}

function NpmStep({ st, onSaved }) {
  const [f, setF] = useState({ npm_url: "", npm_email: "", npm_password: "" });
  const { busy, result, run } = useSaveAndTest();
  return (
    <>
      <h2>Den Proxy Manager verbinden</h2>
      <p className="lead">
        NetworkHelper liest aus dem Proxy Manager, welche Dienste du freigegeben hast (die <Term k="proxy_host">Proxy Hosts</Term>).
        Daraus entstehen automatisch die Überwachung der Erreichbarkeit und die Prüfung der Zertifikate. Geändert wird im Proxy Manager nichts.
      </p>
      {st?.npm && !result && <p className="setup-result ok">✓ Bereits verbunden. Du kannst die Angaben hier ändern oder weitergehen.</p>}
      <form className="form-grid" onSubmit={async (e) => { e.preventDefault(); if (await run(f, "/admin/settings/test-npm", (r) => `Verbunden: ${r.hosts} Dienste gefunden. Die Überwachung startet gleich.`)) onSaved(); }}>
        <label className="span-all">Adresse der Verwaltung
          <input value={f.npm_url} onChange={(e) => setF({ ...f, npm_url: e.target.value })} placeholder="http://192.168.1.10:81" required={!st?.npm} />
          <span className="hint">Die Seite, auf der du dich im Proxy Manager anmeldest. Meist die IP des Containers mit <code>:81</code> am Ende.</span>
        </label>
        <label>E-Mail im Proxy Manager<input value={f.npm_email} onChange={(e) => setF({ ...f, npm_email: e.target.value })} autoComplete="off" required={!st?.npm} /></label>
        <label>Passwort<input type="password" value={f.npm_password} onChange={(e) => setF({ ...f, npm_password: e.target.value })} autoComplete="new-password" required={!st?.npm} /></label>
        <p className="hint span-all">Tipp: Lege im Proxy Manager unter „Users“ ein eigenes Konto für NetworkHelper an und gib ihm unter „Permissions“ nur Leserechte für Proxy Hosts.</p>
        <div className="actions span-all"><button className="btn primary" disabled={busy}>{busy ? "Verbinde …" : "Speichern und testen"}</button></div>
      </form>
      <Result result={result} />
    </>
  );
}

function PorkbunStep({ st, onSaved }) {
  const [f, setF] = useState({ porkbun_api_key: "", porkbun_secret_key: "" });
  const { busy, result, run } = useSaveAndTest();
  return (
    <>
      <h2>Deine Domain bei Porkbun</h2>
      <p className="lead">
        Damit <code>cloud.deine-domain.de</code> bei dir zu Hause ankommt, steht bei Porkbun ein Eintrag im <Term k="dns">DNS</Term>.
        Mit einem <Term k="api_key">API-Schlüssel</Term> legt NetworkHelper diese Einträge für dich an und hält sie aktuell, auch wenn sich deine <Term k="public_ip">öffentliche IP</Term> ändert.
      </p>
      {st?.porkbun && !result && <p className="setup-result ok">✓ Bereits verbunden.</p>}
      <ol className="steps big">
        <li>Melde dich bei <a href="https://porkbun.com/account/api" target="_blank" rel="noreferrer noopener">porkbun.com</a> an und öffne <strong>Account → API Access</strong>.</li>
        <li>Gib einen Namen ein (zum Beispiel „NetworkHelper“) und klicke <strong>Create API Key</strong>. Kopiere beide Werte, das Secret wird nur einmal angezeigt.</li>
        <li>Wichtig: Öffne <strong>Domain Management</strong>, klicke bei deiner Domain auf <strong>Details</strong> und schalte <strong>API Access</strong> ein.</li>
      </ol>
      <form className="form-grid" onSubmit={async (e) => { e.preventDefault(); if (await run(f, "/admin/settings/test-porkbun", (r) => `Verbunden. Deine öffentliche IP ist ${r.ip}, Domains: ${r.domains.join(", ") || "keine mit API-Zugriff"}.`)) onSaved(); }}>
        <label>API Key<input value={f.porkbun_api_key} onChange={(e) => setF({ ...f, porkbun_api_key: e.target.value.trim() })} placeholder="pk1_…" autoComplete="off" required={!st?.porkbun} /></label>
        <label>Secret Key<input type="password" value={f.porkbun_secret_key} onChange={(e) => setF({ ...f, porkbun_secret_key: e.target.value.trim() })} placeholder="sk1_…" autoComplete="new-password" required={!st?.porkbun} /></label>
        <div className="actions span-all"><button className="btn primary" disabled={busy}>{busy ? "Verbinde …" : "Speichern und testen"}</button></div>
      </form>
      <Result result={result} />
      {(st?.porkbun || result?.ok) && st?.npm && (
        <p className="muted small">Unter DNS → „Abgleich mit dem Proxy Manager“ kannst du danach mit einem Klick Einträge für alle deine Dienste anlegen.</p>
      )}
    </>
  );
}

const PROVIDERS = [
  { name: "Gmail", host: "smtp.gmail.com", port: 587, note: "Braucht ein App-Passwort: myaccount.google.com → Sicherheit → App-Passwörter." },
  { name: "GMX", host: "mail.gmx.net", port: 587, note: "In den GMX-Einstellungen „POP3/IMAP und SMTP“ erlauben." },
  { name: "WEB.DE", host: "smtp.web.de", port: 587, note: "In den Einstellungen „POP3/IMAP Abruf“ erlauben." },
  { name: "Outlook", host: "smtp-mail.outlook.com", port: 587, note: "" },
  { name: "Andere", host: "", port: 587, note: "Die Daten findest du in der Hilfe deines Mail-Anbieters unter „SMTP“." },
];

function EmailStep({ st, onSaved }) {
  const [provider, setProvider] = useState(PROVIDERS[0]);
  const [f, setF] = useState({ smtp_user: "", smtp_password: "" });
  const { busy, result, run } = useSaveAndTest();
  const [host, setHost] = useState(PROVIDERS[0].host);
  return (
    <>
      <h2>Warnungen per E-Mail</h2>
      <p className="lead">
        Fällt ein Dienst aus, läuft ein Zertifikat ab oder steht plötzlich eine Tür offen, schickt NetworkHelper dir eine Mail.
        Dafür braucht es ein Postfach, über das er senden darf, am einfachsten dein eigenes.
      </p>
      {st?.smtp && !result && <p className="setup-result ok">✓ E-Mail ist bereits eingerichtet.</p>}
      <div className="chips">
        {PROVIDERS.map((p) => <button key={p.name} type="button" className={`chip ${provider.name === p.name ? "on" : ""}`} onClick={() => { setProvider(p); setHost(p.host); }}>{p.name}</button>)}
      </div>
      {provider.note && <p className="hint">{provider.note}</p>}
      <form className="form-grid" onSubmit={async (e) => {
        e.preventDefault();
        const ok = await run({ ...f, smtp_host: host, smtp_port: provider.port, smtp_starttls: true }, "/admin/settings/test-email", (r) => `Testmail an ${r.to} verschickt. Schau in dein Postfach.`);
        if (ok) onSaved();
      }}>
        {provider.name === "Andere" && <label className="span-all">SMTP-Server<input value={host} onChange={(e) => setHost(e.target.value)} placeholder="smtp.example.de" required /></label>}
        <label>E-Mail-Adresse<input type="email" value={f.smtp_user} onChange={(e) => setF({ ...f, smtp_user: e.target.value })} required autoComplete="off" /></label>
        <label>Passwort{provider.name === "Gmail" ? " (App-Passwort)" : ""}<input type="password" value={f.smtp_password} onChange={(e) => setF({ ...f, smtp_password: e.target.value.replace(/\s/g, "") })} required autoComplete="new-password" /></label>
        <div className="actions span-all"><button className="btn primary" disabled={busy}>{busy ? "Sende …" : "Speichern und Testmail senden"}</button></div>
      </form>
      <Result result={result} />
      <p className="muted small">Die Warnungen gehen an die Adresse deines NetworkHelper-Kontos. Wie viel gemailt wird, stellst du später unter Administration → E-Mail ein.</p>
    </>
  );
}

function Done({ st, onTour, onFinish }) {
  const items = [
    { ok: st?.agents.online > 0, text: "Agent auf dem Proxy Manager", todo: "Zugriffe bleiben leer, bis ein Agent läuft (Verbindungen → Agent hinzufügen)." },
    { ok: st?.npm, text: "Proxy Manager verbunden", todo: "Dienste kannst du auch von Hand unter Erreichbarkeit hinzufügen." },
    { ok: st?.porkbun, text: "Porkbun verbunden", todo: "DNS und DynDNS sind aus, bis die Schlüssel eingetragen sind." },
    { ok: st?.smtp, text: "E-Mail eingerichtet", todo: "Warnungen erscheinen dann nur unter „Meldungen“." },
  ];
  return (
    <>
      <h2>Geschafft</h2>
      <p className="lead">NetworkHelper arbeitet ab jetzt im Hintergrund. Die ersten Prüfungen laufen in den nächsten Minuten, der erste Portscan nach etwa drei Minuten.</p>
      <ul className="check-summary">
        {items.map((i) => (
          <li key={i.text} className={i.ok ? "ok" : "todo"}>
            <span aria-hidden="true">{i.ok ? "✓" : "–"}</span>
            <div><strong>{i.text}</strong>{!i.ok && <p className="muted small">{i.todo}</p>}</div>
          </li>
        ))}
      </ul>
      <div className="actions">
        <button className="btn primary" onClick={onTour}>Kurze Tour durch die Oberfläche</button>
        <button className="btn" onClick={onFinish}>Direkt zur Übersicht</button>
      </div>
    </>
  );
}

export default function Setup() {
  const navigate = useNavigate();
  const { startTour, onUser } = useHelp();
  const [i, setI] = useState(0);
  const step = STEPS[i].key;
  const [st, reload] = useSetupStatus(step === "agent" || step === "done");

  async function finish(withTour) {
    try { onUser(await api.put("/me/onboarding", { onboarding_done: true })); } catch { /* ignorieren */ }
    navigate("/");
    if (withTour) setTimeout(startTour, 300);
  }
  const next = () => { setI((x) => Math.min(STEPS.length - 1, x + 1)); window.scrollTo({ top: 0 }); };

  return (
    <div className="wizard">
      <header className="setup-head">
        <span className="eyebrow">Einrichtung</span>
        <ol className="stepper" aria-label="Schritte">
          {STEPS.map((s, k) => (
            <li key={s.key} className={k === i ? "on" : k < i ? "done" : ""}>
              <button type="button" onClick={() => setI(k)} aria-current={k === i ? "step" : undefined}>
                <span className="stepper-dot">{k < i ? "✓" : k + 1}</span><span className="stepper-label">{s.label}</span>
              </button>
            </li>
          ))}
        </ol>
      </header>
      <section className="panel setup-body" key={step}>
        {step === "welcome" && <Welcome />}
        {step === "agent" && <AgentStep st={st} />}
        {step === "npm" && <NpmStep st={st} onSaved={reload} />}
        {step === "porkbun" && <PorkbunStep st={st} onSaved={reload} />}
        {step === "email" && <EmailStep st={st} onSaved={reload} />}
        {step === "done" && <Done st={st} onTour={() => finish(true)} onFinish={() => finish(false)} />}
      </section>
      {step !== "done" && (
        <div className="setup-nav">
          <button className="link small" onClick={() => finish(false)}>Einrichtung überspringen</button>
          <span className="grow" />
          {i > 0 && <button className="btn" onClick={() => setI(i - 1)}>Zurück</button>}
          <button className="btn primary" onClick={next}>{i === 0 ? "Los geht's" : "Weiter"}</button>
        </div>
      )}
    </div>
  );
}
