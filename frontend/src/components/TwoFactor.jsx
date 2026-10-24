import { useCallback, useEffect, useState } from "react";
import { api, fmtDate } from "../api.js";
import { confirmDialog, Loading, toast } from "./feedback.jsx";
import { Pill } from "./ui.jsx";

const APPS = "zum Beispiel Google Authenticator, Microsoft Authenticator, 2FAS, Aegis oder den Passwort-Manager Bitwarden";

function CodeInput({ value, onChange, autoFocus, label = "6-stelliger Code aus der App", allowRecovery = false }) {
  return (
    <label>
      {label}
      <input className="code-input" value={value} onChange={(e) => onChange(e.target.value)} autoFocus={autoFocus} required
             inputMode={allowRecovery ? "text" : "numeric"} autoComplete="one-time-code" maxLength={allowRecovery ? 14 : 7}
             placeholder={allowRecovery ? "123456 oder ABCDE-FGHJK" : "123456"} spellCheck={false} />
    </label>
  );
}

function RecoveryCodes({ codes, onDone }) {
  const [saved, setSaved] = useState(false);
  const text = `NetworkHelper – Wiederherstellungscodes\nJeder Code funktioniert genau einmal.\n\n${codes.join("\n")}\n`;
  function download() {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    a.download = "networkhelper-wiederherstellungscodes.txt";
    a.click();
    URL.revokeObjectURL(a.href);
    setSaved(true);
  }
  async function copy() {
    try { await navigator.clipboard.writeText(text); toast("Kopiert."); setSaved(true); } catch { toast("Kopieren ging nicht, bitte abschreiben oder herunterladen.", "error"); }
  }
  return (
    <div className="tfa-step">
      <h3 className="sub-title">Wiederherstellungscodes sichern</h3>
      <p className="small">Falls du dein Handy verlierst, kommst du mit einem dieser Codes trotzdem hinein. Jeder Code funktioniert genau einmal. <strong>Sie werden nur jetzt angezeigt.</strong> Lege sie in deinen Passwort-Manager oder drucke sie aus.</p>
      <ol className="recovery-codes">{codes.map((c) => <li key={c} className="mono">{c}</li>)}</ol>
      <div className="actions">
        <button type="button" className="btn" onClick={download}>Als Datei speichern</button>
        <button type="button" className="btn" onClick={copy}>Kopieren</button>
        <button type="button" className="btn" onClick={() => { window.print(); setSaved(true); }}>Drucken</button>
      </div>
      <label className="check"><input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} /> Ich habe die Codes sicher abgelegt</label>
      <div className="actions"><button type="button" className="btn primary" disabled={!saved} onClick={onDone}>Fertig</button></div>
    </div>
  );
}

/** Einrichten, Verwalten und Ausschalten der Zwei-Faktor-Anmeldung. */
export default function TwoFactor({ onChanged, forced = false }) {
  const [st, setSt] = useState(null);
  const [step, setStep] = useState("idle"); // idle | password | scan | codes | disable | renew
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [setup, setSetup] = useState(null);
  const [codes, setCodes] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => api.get("/me/2fa").then(setSt).catch((e) => setError(e.message)), []);
  useEffect(() => { load(); }, [load]);

  const reset = () => { setStep("idle"); setPassword(""); setCode(""); setSetup(null); setError(""); };
  async function run(fn) {
    setError(""); setBusy(true);
    try { await fn(); } catch (e) { setError(e.message); } finally { setBusy(false); }
  }

  const start = (e) => { e.preventDefault(); run(async () => { setSetup(await api.post("/me/2fa/setup", { password })); setPassword(""); setStep("scan"); }); };
  const enable = (e) => {
    e.preventDefault();
    run(async () => {
      const r = await api.post("/me/2fa/enable", { code });
      setCodes(r.recovery_codes); setSt(r.status); setCode(""); setStep("codes");
    });
  };
  const disable = (e) => {
    e.preventDefault();
    run(async () => {
      if (!(await confirmDialog("Danach reicht wieder das Passwort allein zum Anmelden.", { title: "Zwei-Faktor-Anmeldung ausschalten?", confirmLabel: "Ausschalten" }))) return;
      const r = await api.post("/me/2fa/disable", { password, code }); setSt(r.status); reset(); toast("Zwei-Faktor-Anmeldung ist aus."); onChanged?.();
    });
  };
  const renew = (e) => {
    e.preventDefault();
    run(async () => { const r = await api.post("/me/2fa/recovery", { password, code }); setCodes(r.recovery_codes); setSt(r.status); setPassword(""); setCode(""); setStep("codes"); });
  };

  if (!st) return error ? <p className="error">{error}</p> : <Loading rows={1} />;

  if (step === "codes" && codes) {
    return <RecoveryCodes codes={codes} onDone={() => { setCodes(null); reset(); toast("Zwei-Faktor-Anmeldung ist aktiv."); onChanged?.(); }} />;
  }

  if (st.enabled) {
    return (
      <div className="tfa">
        <p><Pill tone="ok">Aktiv</Pill> <span className="muted small">seit {fmtDate(st.enabled_at)} · noch {st.recovery_left} Wiederherstellungscodes</span></p>
        {st.recovery_left <= 3 && <p className="small tone-warn">Es sind nur noch wenige Wiederherstellungscodes übrig. Erzeuge neue.</p>}
        {step === "idle" && (
          <div className="actions">
            <button className="btn" onClick={() => setStep("renew")}>Neue Wiederherstellungscodes</button>
            {!st.required && <button className="btn danger-outline" onClick={() => setStep("disable")}>Ausschalten</button>}
          </div>
        )}
        {(step === "disable" || step === "renew") && (
          <form className="form-grid" onSubmit={step === "disable" ? disable : renew}>
            <label>Passwort<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required /></label>
            <CodeInput value={code} onChange={setCode} allowRecovery label="Code aus der App oder Wiederherstellungscode" />
            {error && <p className="error span-all" role="alert">{error}</p>}
            <div className="actions span-all">
              <button className={`btn ${step === "disable" ? "danger-btn" : "primary"}`} disabled={busy}>{step === "disable" ? "Ausschalten" : "Neue Codes erzeugen"}</button>
              <button type="button" className="btn" onClick={reset}>Abbrechen</button>
            </div>
          </form>
        )}
      </div>
    );
  }

  return (
    <div className="tfa">
      {step === "idle" && (
        <>
          <p className="small">Mit der Zwei-Faktor-Anmeldung reicht ein gestohlenes Passwort nicht mehr: Beim Anmelden fragt NetworkHelper zusätzlich nach einem Code, den eine App auf deinem Handy alle 30 Sekunden neu erzeugt ({APPS}).</p>
          {!forced && <p><Pill tone="due">Aus</Pill></p>}
          <div className="actions"><button className="btn primary" onClick={() => setStep("password")}>Jetzt einrichten</button></div>
        </>
      )}
      {step === "password" && (
        <form className="form-grid" onSubmit={start}>
          <label className="span-all">Zur Sicherheit: dein Passwort<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required autoFocus /></label>
          {error && <p className="error span-all" role="alert">{error}</p>}
          <div className="actions span-all"><button className="btn primary" disabled={busy}>Weiter</button><button type="button" className="btn" onClick={reset}>Abbrechen</button></div>
        </form>
      )}
      {step === "scan" && setup && (
        <form className="tfa-step" onSubmit={enable}>
          <ol className="tfa-howto">
            <li>Öffne deine Authenticator-App ({APPS}) und tippe auf „+“ bzw. „Konto hinzufügen“.</li>
            <li>Scanne diesen QR-Code. Am Handy selbst kannst du stattdessen den Schlüssel unten abtippen.</li>
            <li>Gib den 6-stelligen Code ein, den die App jetzt für „NetworkHelper“ anzeigt.</li>
          </ol>
          <div className="tfa-qr-row">
            <div className="tfa-qr" dangerouslySetInnerHTML={{ __html: setup.qr_svg }} role="img" aria-label="QR-Code für die Authenticator-App" />
            <div className="grow">
              <div className="field-label">Schlüssel zum Abtippen</div>
              <div className="mono tfa-secret">{setup.secret}</div>
              <a className="small" href={setup.uri}>Auf diesem Gerät in der App öffnen</a>
              <CodeInput value={code} onChange={setCode} autoFocus />
              {error && <p className="error" role="alert">{error}</p>}
              <div className="actions"><button className="btn primary" disabled={busy}>Bestätigen</button><button type="button" className="btn" onClick={reset}>Abbrechen</button></div>
            </div>
          </div>
        </form>
      )}
    </div>
  );
}

/** Ganze Seite, wenn der Administrator die Zwei-Faktor-Anmeldung für alle vorschreibt. */
export function TwoFactorGate({ user, onDone, onLogout }) {
  return (
    <div className="gate">
      <section className="panel">
        <h1>Zwei-Faktor-Anmeldung einrichten</h1>
        <p>Der Administrator hat festgelegt, dass alle Konten eine Zwei-Faktor-Anmeldung brauchen. Angemeldet als <strong>{user.email}</strong>. Danach geht es direkt weiter.</p>
        <TwoFactor forced onChanged={onDone} />
        <div className="actions"><button className="link" onClick={onLogout}>Abmelden</button></div>
      </section>
    </div>
  );
}
