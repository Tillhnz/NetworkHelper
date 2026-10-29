import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, fmtAgo, fmtDate, fmtDateTime } from "../api.js";
import { Loading, confirmDialog, toast } from "../components/feedback.jsx";
import { Pill } from "../components/ui.jsx";

const ROLE_TEXT = { admin: "Administrator", user: "Nutzer" };

/** Ein Block mit Einstellungsfeldern, der gemeinsam gespeichert wird. */
function SettingsBlock({ title, intro, defs, spec, onSaved, extra, children }) {
  const initial = () =>
    Object.fromEntries(spec.map((f) => [f.key, f.secret ? "" : defs[f.key]?.value ?? (f.type === "bool" ? false : "")]));
  const [form, setForm] = useState(initial);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => { setForm(initial()); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [defs]);

  async function save(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const values = {};
      for (const f of spec) {
        if (f.secret) { if (form[f.key] !== "") values[f.key] = form[f.key]; } else values[f.key] = form[f.key];
      }
      await onSaved(values);
      toast("Gespeichert. Die Änderung gilt sofort.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel">
      <h2>{title}</h2>
      {intro && <div className="muted small intro">{intro}</div>}
      <form className="form-grid" onSubmit={save}>
        {spec.map((f) => {
          const def = defs[f.key];
          if (f.type === "bool") {
            return (
              <label key={f.key} className="check span-all">
                <input type="checkbox" checked={!!form[f.key]} onChange={(e) => setForm({ ...form, [f.key]: e.target.checked })} />
                <span>{f.label}{f.hint && <span className="hint block">{f.hint}</span>}</span>
              </label>
            );
          }
          if (f.type === "select") {
            return (
              <label key={f.key} className={f.wide ? "span-all" : ""}>
                {f.label}
                <select value={form[f.key] ?? ""} onChange={(e) => setForm({ ...form, [f.key]: e.target.value })}>
                  {f.options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                </select>
                {f.hint && <span className="hint">{f.hint}</span>}
              </label>
            );
          }
          return (
            <label key={f.key} className={f.wide ? "span-all" : ""}>
              {f.label}
              <input
                type={f.secret ? "password" : f.type === "number" ? "number" : "text"}
                value={form[f.key] ?? ""}
                placeholder={f.secret ? (def?.set ? "gespeichert, leer lassen zum Behalten" : "") : f.placeholder}
                onChange={(e) => setForm({ ...form, [f.key]: e.target.value })}
                autoComplete="off" min={f.min} max={f.max}
              />
              {f.hint && <span className="hint">{f.hint}</span>}
              {f.secret && def?.set && (
                <button type="button" className="link small" onClick={() => onSaved({ [f.key]: "" }).then(() => toast(`${f.label} gelöscht.`)).catch((er) => setError(er.message))}>
                  gespeicherten Wert löschen
                </button>
              )}
            </label>
          );
        })}
        <div className="actions span-all">
          <button className="btn primary" disabled={busy}>Speichern</button>
          {extra}
        </div>
      </form>
      {error && <p className="error" role="alert">{error}</p>}
      {children}
    </section>
  );
}

function TestButton({ label, path, describe }) {
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);
  async function run() {
    setBusy(true);
    setMsg(null);
    try { setMsg({ ok: true, text: describe(await api.post(path, {})) }); } catch (e) { setMsg({ ok: false, text: e.message }); } finally { setBusy(false); }
  }
  return (
    <>
      <button type="button" className="btn" onClick={run} disabled={busy}>{busy ? "Teste …" : label}</button>
      {msg && <span className={msg.ok ? "ok" : "error"} role="status">{msg.text}</span>}
    </>
  );
}

function Accounts() {
  const [users, setUsers] = useState([]);
  const [error, setError] = useState("");
  const load = useCallback(() => api.get("/admin/users").then(setUsers).catch((e) => setError(e.message)), []);
  useEffect(() => { load(); }, [load]);
  const run = async (fn, done) => { setError(""); try { await fn(); if (done) toast(done); await load(); } catch (err) { setError(err.message); } };
  return (
    <section className="panel">
      <h2>Konten und Rollen ({users.length})</h2>
      <p className="muted small">Administratoren ändern Einstellungen, Agenten, Sperrliste und DNS. Nutzer sehen alles, ändern aber nichts.</p>
      <ul className="log-list">
        {users.map((u) => (
          <li key={u.id}>
            <span>
              <strong>{u.email}</strong> <Pill tone={u.role === "admin" ? "ok" : "muted"}>{ROLE_TEXT[u.role]}</Pill>
              {!u.active && <> <Pill tone="due">Gesperrt</Pill></>}
              {" "}{u.two_factor ? <Pill tone="ok">2FA</Pill> : <Pill tone="soon">ohne 2FA</Pill>}
              <span className="muted small"> seit {fmtDate(u.created_at)}{u.is_me ? ", das bist du" : ""}</span>
            </span>
            {!u.is_me && (
              <span className="rule-actions">
                <button className="link small" onClick={() => run(() => api.put(`/admin/users/${u.id}`, { role: u.role === "admin" ? "user" : "admin" }), "Rolle geändert.")}>
                  {u.role === "admin" ? "Zum Nutzer machen" : "Zum Administrator machen"}
                </button>
                <button className="link small" onClick={() => run(() => api.put(`/admin/users/${u.id}`, { active: !u.active }), u.active ? "Konto gesperrt." : "Konto entsperrt.")}>
                  {u.active ? "Sperren" : "Entsperren"}
                </button>
                {u.two_factor && (
                  <button className="link small" onClick={async () => { if (await confirmDialog(`Die Zwei-Faktor-Anmeldung von ${u.email} wird ausgeschaltet und das Konto überall abgemeldet. Danach reicht wieder das Passwort. Nur nutzen, wenn die Person Handy und Wiederherstellungscodes verloren hat.`, { title: "2FA zurücksetzen?", confirmLabel: "Zurücksetzen" })) run(() => api.del(`/admin/users/${u.id}/2fa`), "Zwei-Faktor-Anmeldung zurückgesetzt."); }}>2FA zurücksetzen</button>
                )}
                <button className="link small danger" onClick={async () => { if (await confirmDialog(`Konto ${u.email} löschen?`)) run(() => api.del(`/admin/users/${u.id}`), "Konto gelöscht."); }}>Löschen</button>
              </span>
            )}
          </li>
        ))}
      </ul>
      {error && <p className="error" role="alert">{error}</p>}
    </section>
  );
}

function Invites() {
  const [invites, setInvites] = useState(null);
  const load = useCallback(() => api.get("/admin/invites").then(setInvites).catch((e) => toast(e.message, "error")), []);
  useEffect(() => { load(); }, [load]);
  const link = (code) => `${window.location.origin}/login?invite=${code}`;
  return (
    <section className="panel">
      <h2>Einladungen</h2>
      <p className="muted small">Ist die offene Registrierung aus, kommen neue Nutzer nur mit einem Einladungscode hinein. Jeder Code gilt einmal.</p>
      <div className="actions"><button className="btn primary" onClick={async () => { await api.post("/admin/invites", {}); load(); }}>Neue Einladung erzeugen</button></div>
      {invites?.length > 0 && (
        <ul className="log-list">
          {invites.map((i) => (
            <li key={i.id}>
              <span><strong className="mono">{i.code}</strong> <span className="muted">{i.used_by_email ? `verwendet von ${i.used_by_email}` : "offen"}</span></span>
              <span className="rule-actions">
                {!i.used_by_email && <button className="link small" onClick={() => navigator.clipboard.writeText(link(i.code)).then(() => toast("Einladungslink kopiert."))}>Link kopieren</button>}
                <button className="link small danger" onClick={async () => { await api.del(`/admin/invites/${i.id}`); load(); }}>Löschen</button>
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function Updates() {
  const [st, setSt] = useState(null);
  const [error, setError] = useState("");
  const [checking, setChecking] = useState(false);
  const [watching, setWatching] = useState(false);
  const load = useCallback(async (check = false) => {
    try { const r = await api.get(`/admin/update${check ? "?check=true" : ""}`); setSt(r); setError(""); return r; } catch (e) { setError(e.message); return null; }
  }, []);
  useEffect(() => { load(false); }, [load]);
  useEffect(() => {
    if (!watching) return undefined;
    const id = setInterval(async () => {
      try {
        const r = await api.get("/admin/update");
        setSt(r);
        setError("");
        if (r.job.state === "done") { setWatching(false); setTimeout(() => window.location.reload(), 1500); }
        if (r.job.state === "failed") setWatching(false);
      } catch { setError(""); }
    }, 3000);
    return () => clearInterval(id);
  }, [watching]);
  async function start() {
    if (!(await confirmDialog("Die Seite ist dabei ein bis zwei Minuten nicht erreichbar. Die Überwachung pausiert so lange.", { title: "NetworkHelper jetzt aktualisieren?", confirmLabel: "Aktualisieren", danger: false }))) return;
    try {
      await api.post("/admin/update", {});
      setWatching(true);
      setSt((s) => ({ ...s, job: { ...(s?.job || {}), state: "running", log: "", error: null } }));
    } catch (e) { setError(e.message); }
  }
  const v = st?.version;
  const job = st?.job;
  const busy = watching || job?.state === "running" || job?.state === "restarting";
  return (
    <section className="panel">
      <h2>Updates</h2>
      {v && <p>Installierte Version: <strong className="mono">{v.commit}</strong> <span className="muted small">vom {fmtDate(v.date)}, {v.subject}</span></p>}
      {st?.dirty && <p className="error">Im Projektordner gibt es lokale Änderungen. Das Update bricht dann ab.</p>}
      {st?.check_error && <p className="error" role="alert">{st.check_error}</p>}
      {st?.behind === 0 && <p className="ok">NetworkHelper ist auf dem neuesten Stand.</p>}
      {st?.behind > 0 && (
        <>
          <p><strong>{st.behind} {st.behind === 1 ? "neue Änderung" : "neue Änderungen"}</strong> verfügbar:</p>
          <ul className="log-list">{st.changes.map((c) => <li key={c}><span>{c}</span></li>)}</ul>
        </>
      )}
      {busy && <p role="status">{job?.state === "restarting" ? "Starte neu … die Seite lädt gleich von selbst." : "Update läuft … das dauert einige Minuten."}</p>}
      {job?.state === "failed" && <p className="error" role="alert">{job.error}</p>}
      {job?.state === "failed" && job.log && <details><summary className="small">Protokoll</summary><pre className="code-block">{job.log}</pre></details>}
      {error && <p className="error" role="alert">{error}</p>}
      <div className="actions">
        <button className="btn" onClick={async () => { setChecking(true); await load(true); setChecking(false); }} disabled={busy || checking}>{checking ? "Prüfe …" : "Nach Updates suchen"}</button>
        <button className="btn primary" onClick={start} disabled={busy || st?.behind === 0 || !st}>Jetzt aktualisieren</button>
      </div>
      <p className="muted small">Das Update sichert zuerst die Datenbank, holt die neue Version von GitHub und baut sie neu. Springt sie nicht an, geht NetworkHelper automatisch zur vorherigen zurück.</p>
    </section>
  );
}

const JOB_TEXT = {
  uptime: "Erreichbarkeit", detect: "Erkennung auffälliger Zugriffe", alerts: "Mailversand", agents: "Agenten-Überwachung",
  npm_sync: "Abgleich mit dem Proxy Manager", dyndns: "DynDNS", sitecheck: "Zertifikate und Header", portscan: "Portscan", maintenance: "Aufräumen und GeoIP",
};

function Health() {
  const [h, setH] = useState(null);
  const [error, setError] = useState("");
  const load = useCallback(() => api.get("/admin/health").then(setH).catch((e) => setError(e.message)), []);
  useEffect(() => { load(); }, [load]);
  async function run(name) {
    try { await api.post(`/admin/jobs/${name}`, {}); toast(`${JOB_TEXT[name]} gestartet.`); setTimeout(load, 3000); } catch (e) { toast(e.message, "error"); }
  }
  if (error) return <section className="panel"><h2>Zustand</h2><p className="error">{error}</p></section>;
  if (!h) return <Loading rows={1} />;
  const up = h.uptime_s;
  return (
    <section className="panel">
      <h2>Zustand</h2>
      <ul className="log-list">
        {h.checks.map((c) => (
          <li key={c.key}><span>{c.label}</span><span><Pill tone={c.ok ? "ok" : "due"}>{c.ok ? "In Ordnung" : "Prüfen"}</Pill> <span className="muted small">{c.text}</span></span></li>
        ))}
        {h.db_bytes != null && <li><span>Größe der Datenbank</span><span className="muted small">{(h.db_bytes / 1e6).toFixed(1)} MB</span></li>}
        <li><span>Läuft seit</span><span className="muted small">{up >= 86400 ? `${Math.floor(up / 86400)} Tagen` : up >= 3600 ? `${Math.floor(up / 3600)} Stunden` : `${Math.max(1, Math.floor(up / 60))} Minuten`}</span></li>
      </ul>
      <h3 className="sub-title">Hintergrundaufgaben</h3>
      <ul className="log-list">
        {h.jobs.map((j) => (
          <li key={j.name}>
            <span>{JOB_TEXT[j.name] || j.name}{j.error && <span className="error small block">{j.error}</span>}</span>
            <span className="rule-actions">
              <span className="muted small">{j.running ? "läuft gerade" : j.last_run ? fmtAgo(j.last_run) : "noch nicht gelaufen"}</span>
              <button className="link small" onClick={() => run(j.name)} disabled={j.running}>Jetzt</button>
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

function Backups() {
  const [items, setItems] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => api.get("/admin/backups").then((r) => { setItems(r.items); setError(""); }).catch((e) => setError(e.message)), []);
  useEffect(() => { load(); }, [load]);
  async function create() {
    setBusy(true);
    try { const r = await api.post("/admin/backups", {}); toast(`Gesichert: ${r.name}`); await load(); } catch (e) { toast(e.message, "error"); } finally { setBusy(false); }
  }
  return (
    <section className="panel">
      <h2>Sicherungen</h2>
      <p className="muted small">Sicherungen liegen im Ordner <code>backups</code> auf dem Server. Vor jedem Update entsteht automatisch eine, die letzten 14 bleiben. Zurückspielen: <code>./install.sh restore backups/DATEI</code>.</p>
      <div className="actions"><button className="btn" onClick={create} disabled={busy}>{busy ? "Sichere …" : "Jetzt sichern"}</button></div>
      {error && <p className="error">{error}</p>}
      {items?.length === 0 && <p className="muted small">Noch keine Sicherung.</p>}
      {items?.length > 0 && <ul className="log-list">{items.slice(0, 8).map((b) => <li key={b.name}><span>{fmtDateTime(b.at)}</span><span className="muted small">{(b.bytes / 1e6).toFixed(1)} MB, {b.name}</span></li>)}</ul>}
    </section>
  );
}

const ACTION_TEXT = {
  "invite.create": "Einladung erstellt", "invite.delete": "Einladung gelöscht", "user.role": "Rolle geändert", "user.lock": "Konto gesperrt",
  "user.unlock": "Konto entsperrt", "user.delete": "Konto gelöscht", "user.register": "Konto angelegt", "settings.save": "Einstellungen gespeichert",
  "update.start": "Update gestartet", "backup.create": "Sicherung erstellt", "agent.create": "Agent angelegt", "agent.delete": "Agent entfernt",
  "agent.token": "Agent-Token erneuert", "block.add": "Adresse gesperrt", "block.remove": "Sperre aufgehoben", "dns.create": "DNS-Record angelegt",
  "dns.edit": "DNS-Record geändert", "dns.delete": "DNS-Record gelöscht", "dns.npm": "DNS für Proxy Hosts angelegt",
  "port.expected": "Port als erwartet markiert", "port.unexpected": "Port nicht mehr erwartet",
};

function AuditLog() {
  const [rows, setRows] = useState(null);
  useEffect(() => { api.get("/admin/audit?limit=200").then(setRows).catch((e) => toast(e.message, "error")); }, []);
  return (
    <section className="panel">
      <h2>Protokoll</h2>
      <p className="muted small">Verwaltungsvorgänge: wer wann was geändert hat. Passwörter und Schlüssel stehen nie darin.</p>
      {!rows ? <Loading rows={2} /> : rows.length === 0 ? <p className="muted small">Noch nichts protokolliert.</p> : (
        <ul className="log-list">
          {rows.map((r) => (
            <li key={r.id}>
              <span><strong>{ACTION_TEXT[r.action] || r.action}</strong>{r.detail && <span className="muted small"> {r.detail}</span>}</span>
              <span className="muted small">{fmtDateTime(r.at)}, {r.actor}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

const ACCESS = [
  { key: "allow_registration", type: "bool", label: "Jeder darf sich selbst registrieren", hint: "Aus: nur mit Einladung. Das erste Konto ist immer erlaubt." },
  { key: "token_expire_days", type: "number", label: "Anmeldung gilt (Tage)", min: 1, max: 90 },
  { key: "trusted_proxies", type: "number", label: "Proxys vor NetworkHelper", min: 0, max: 5, hint: "1, wenn NetworkHelper über den Nginx Proxy Manager erreichbar ist, sonst 0." },
];
const EMBED = [
  { key: "frame_ancestors", type: "text", wide: true, label: "Diese Seiten dürfen NetworkHelper einbetten", placeholder: "https://ha.example.de http://192.168.1.20:8123",
    hint: "Zum Beispiel Home Assistant (Webseiten-Karte oder Seitenleiste). Trage jede Adresse ein, unter der du die Seite öffnest, mit Leerzeichen getrennt. Leer: Einbetten ist verboten (Schutz vor Klick-Tricks fremder Seiten)." },
  { key: "cookie_samesite", type: "select", label: "Anmeldung im eingebetteten Fenster", options: [["strict", "Nur gleiche Domain (am sichersten)"], ["lax", "Gleiche Domain, Links von außen erlaubt"], ["none", "Auch fremde Domains (z. B. HA per IP-Adresse)"]],
    hint: "Liegen Home Assistant und NetworkHelper unter derselben Domain (ha.example.de und network.example.de), reicht die erste Stufe. Öffnest du Home Assistant per IP-Adresse oder über Nabu Casa, wähle die letzte; das funktioniert nur, wenn NetworkHelper über https erreichbar ist. Gilt ab der nächsten Anmeldung." },
];
const GENERAL = [
  { key: "public_url", type: "text", label: "Adresse von NetworkHelper", wide: true, placeholder: "https://network.example.de", hint: "Für Links in Mails und als Vorschlag im Installationsbefehl der Agenten." },
  { key: "timezone", type: "text", label: "Zeitzone", placeholder: "Europe/Berlin" },
  { key: "router_type", type: "select", label: "Dein Router", options: [["fritzbox", "FRITZ!Box"], ["other", "Anderer Router"]], hint: "Für passende Anleitungen zum Schließen offener Ports." },
  { key: "retention_days", type: "number", label: "Zugriffe aufbewahren (Tage)", min: 1, max: 400, hint: "Ältere Einträge werden gelöscht." },
  { key: "geoip_enabled", type: "bool", label: "Land und Netzbetreiber ermitteln (DB-IP, offline)", hint: "Lädt einmal im Monat zwei Dateien von db-ip.com. Danach bleibt jede Abfrage auf dem Server." },
  { key: "geoip_city", type: "bool", label: "Städte für die Herkunftskarte (rund 130 MB)", hint: "Zeigt die Punkte auf der Karte am ungefähren Ort statt in der Landesmitte. Wird nach dem Speichern im Hintergrund geladen." },
];
const EMAIL = [
  { key: "smtp_host", type: "text", label: "SMTP-Server", placeholder: "smtp.gmail.com" },
  { key: "smtp_port", type: "number", label: "Port", min: 1, max: 65535, hint: "587 (STARTTLS) oder 465 (verschlüsselt von Anfang an)." },
  { key: "smtp_user", type: "text", label: "Benutzername", hint: "Meist deine E-Mail-Adresse." },
  { key: "smtp_password", type: "text", secret: true, label: "Passwort", hint: "Bei Gmail ein App-Passwort, nicht das Login-Passwort." },
  { key: "smtp_from", type: "text", label: "Absenderadresse", hint: "Leer: der Benutzername." },
  { key: "alert_min_severity", type: "select", label: "Mailen ab", options: [["info", "Hinweis (alles)"], ["warn", "Warnung"], ["crit", "Nur kritisch"]] },
  { key: "smtp_starttls", type: "bool", label: "Verbindung mit STARTTLS verschlüsseln (Port 587)" },
];
const REPORT = [
  { key: "weekly_report", type: "bool", label: "Wochenbericht per E-Mail schicken", hint: "Eine kurze Zusammenfassung: Sicherheitsstand, was los war und was du dir ansehen solltest." },
  { key: "weekly_report_day", type: "select", label: "Tag", options: [["0", "Montag"], ["1", "Dienstag"], ["2", "Mittwoch"], ["3", "Donnerstag"], ["4", "Freitag"], ["5", "Samstag"], ["6", "Sonntag"]] },
  { key: "weekly_report_hour", type: "number", label: "Uhrzeit (Stunde)", min: 0, max: 23 },
];

function ReportPreview() {
  const [p, setP] = useState(null);
  return (
    <div className="actions">
      <button className="btn" onClick={async () => { try { setP(await api.get("/admin/report/preview")); } catch (e) { toast(e.message, "error"); } }}>Vorschau ansehen</button>
      <TestButton label="Jetzt an mich senden" path="/admin/report/send" describe={(r) => `Gesendet an ${r.sent_to}.`} />
      {p && <pre className="report-preview"><strong>{p.title}</strong>{"\n\n"}{p.body}</pre>}
    </div>
  );
}

const DNS = [
  { key: "porkbun_api_key", type: "text", secret: true, label: "API-Schlüssel (pk1_…)" },
  { key: "porkbun_secret_key", type: "text", secret: true, label: "Secret (sk1_…)" },
  { key: "porkbun_domains", type: "text", label: "Domains", wide: true, placeholder: "example.de, beispiel.com", hint: "Leer: alle Domains des Kontos. Bei jeder Domain muss in Porkbun unter „Details“ der API-Zugriff eingeschaltet sein." },
  { key: "dyndns_enabled", type: "bool", label: "DynDNS: markierte Records bei neuer öffentlicher IP automatisch nachziehen" },
  { key: "dyndns_interval_min", type: "number", label: "DynDNS prüfen alle (Minuten)", min: 1, max: 1440 },
  { key: "dns_new_record_type", type: "select", label: "Neue Records für Proxy Hosts", options: [["A", "A-Record mit öffentlicher IP (DynDNS)"], ["CNAME", "CNAME auf die Hauptdomain"]] },
  { key: "public_ip_override", type: "text", label: "Öffentliche IP fest vorgeben (optional)", placeholder: "leer = automatisch", hint: "Nur nötig, wenn die automatische Erkennung falsch liegt." },
];
const ADGUARD = [
  { key: "adguard_url", type: "text", label: "Adresse der Weboberfläche", wide: true, placeholder: "http://192.168.178.53", hint: "So, wie du AdGuard Home im Browser öffnest (mit Port, falls nicht 80)." },
  { key: "adguard_user", type: "text", label: "Benutzername" },
  { key: "adguard_password", type: "text", secret: true, label: "Passwort" },
];
const NPM = [
  { key: "npm_url", type: "text", label: "Adresse der Verwaltung", wide: true, placeholder: "http://192.168.1.10:81", hint: "Die Adminoberfläche des Proxy Managers, meist Port 81." },
  { key: "npm_email", type: "text", label: "E-Mail des Kontos" },
  { key: "npm_password", type: "text", secret: true, label: "Passwort", hint: "Am besten ein eigenes Konto im Proxy Manager. Zum Ansehen reicht „Nur ansehen“ bei Proxy Hosts und Zertifikaten; zum Erneuern braucht es bei Zertifikaten „Verwalten“." },
  { key: "npm_auto_monitors", type: "bool", label: "Für jeden Proxy Host automatisch die Erreichbarkeit überwachen" },
  { key: "cert_auto_renew", type: "bool", label: "Zertifikate rechtzeitig selbst erneuern", hint: "Klappt die Erneuerung im Proxy Manager nicht, versucht NetworkHelper es selbst (höchstens alle 12 Stunden) und erklärt dir den Grund. Das Konto braucht bei „Zertifikate“ das Recht „Verwalten“." },
  { key: "cert_auto_renew_days", type: "number", label: "Erneuern, wenn weniger als so viele Tage übrig sind", min: 1, max: 60 },
  { key: "npm_auto_dns", type: "bool", label: "Fehlende DNS-Records bei Porkbun automatisch anlegen", hint: "Sobald du im Proxy Manager einen Host für eine deiner Domains anlegst, entsteht der Record innerhalb von 10 Minuten." },
];
const SECURITY = [
  { key: "scan_enabled", type: "bool", label: "Öffentliche IP regelmäßig auf offene Ports prüfen" },
  { key: "scan_interval_h", type: "number", label: "Portscan alle (Stunden)", min: 1, max: 168 },
  { key: "scan_ports", type: "text", label: "Ports", wide: true, placeholder: "leer = rund 100 häufige Ports", hint: "Liste oder Bereiche, z. B. 1-1024, 3389, 8006, 32400." },
  { key: "scan_targets", type: "text", label: "Weitere Ziele", wide: true, placeholder: "z. B. vps.example.de", hint: "Die eigene öffentliche IP ist immer dabei." },
  { key: "shodan_enabled", type: "bool", label: "Shodan InternetDB fragen (sendet nur die öffentliche IP)" },
  { key: "site_check_interval_h", type: "number", label: "Zertifikate prüfen alle (Stunden)", min: 1, max: 168 },
  { key: "fail2ban_share", type: "bool", label: "Sperren von fail2ban überall übernehmen", hint: "Sperrt fail2ban auf einem Server einen Angreifer, sperrt NetworkHelper ihn für 24 Stunden auch im Proxy Manager und auf allen anderen Servern." },
  { key: "app_check_enabled", type: "bool", label: "Apps auf Updates und bekannte Sicherheitslücken prüfen", hint: "Liest die Versionen deiner Apps ab und fragt zweimal am Tag bei GitHub nach neuen Versionen und Sicherheitswarnungen." },
  { key: "github_token", type: "text", secret: true, label: "GitHub-Token (optional)", hint: "Nur nötig bei sehr vielen Apps: Ohne Token erlaubt GitHub 60 Abfragen pro Stunde. Ein Token ohne besondere Rechte reicht." },
  { key: "two_factor_required", type: "bool", label: "Zwei-Faktor-Anmeldung für alle Konten vorschreiben", hint: "Wer sie noch nicht hat, muss sie bei der nächsten Anmeldung einrichten, bevor es weitergeht. Geht erst, wenn dein eigenes Konto sie hat." },
  { key: "exposure_enabled", type: "bool", label: "Selbsttest auf lesbare Geheimnisse (.env, .git, Sicherungen …)", hint: "Ruft bei deinen eigenen Seiten die Adressen auf, die Angreifer ausprobieren, und prüft den Inhalt. Nur GET-Anfragen, nichts wird gespeichert." },
  { key: "exposure_interval_h", type: "number", label: "Selbsttest alle (Stunden)", min: 1, max: 168 },
  { key: "monitor_interval_s", type: "number", label: "Erreichbarkeit prüfen alle (Sekunden)", min: 20, max: 3600 },
  { key: "detect_enabled", type: "bool", label: "Auffällige Zugriffe erkennen" },
  { key: "auto_block", type: "bool", label: "Angreifer automatisch sperren", hint: "Bei Anmeldeversuchen, Angriffswerkzeugen und vielen Schwachstellen-Suchen. Wirkt nur, wenn ein Agent die Sperrliste umsetzt." },
  { key: "auto_block_hours", type: "number", label: "Automatische Sperre gilt (Stunden)", min: 1, max: 8760 },
];

const TABS = [["overview", "Übersicht"], ["accounts", "Konten"], ["general", "Allgemein"], ["email", "E-Mail"], ["dns", "DNS"], ["npm", "Proxy Manager"], ["security", "Sicherheit"], ["log", "Protokoll"]];

export default function Admin({ user }) {
  const [params, setParams] = useSearchParams();
  const tab = TABS.some(([k]) => k === params.get("tab")) ? params.get("tab") : "overview";
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const load = useCallback(() => api.get("/admin/settings").then(setData).catch((e) => setError(e.message)), []);
  useEffect(() => { load(); }, [load]);
  const save = async (values) => setData(await api.put("/admin/settings", { values }));

  if (user.role !== "admin") return <p className="error">Dieser Bereich ist nur für Administratoren.</p>;
  const defs = data?.fields;
  const block = (props) => <SettingsBlock {...props} defs={defs} onSaved={save} />;
  const needsDefs = !["overview", "accounts", "log"].includes(tab);
  return (
    <>
      <header className="page-head"><h1>Administration</h1></header>
      {error && <p className="error" role="alert">{error}</p>}
      <div className="tabs" role="tablist" aria-label="Bereiche der Administration">
        {TABS.map(([k, label]) => (
          <button key={k} role="tab" aria-selected={tab === k} className={`tab ${tab === k ? "on" : ""}`} onClick={() => setParams(k === "overview" ? {} : { tab: k })}>{label}</button>
        ))}
      </div>
      {tab === "overview" && <><Health /><Updates /><Backups /></>}
      {tab === "accounts" && <><Accounts /><Invites /></>}
      {tab === "log" && <AuditLog />}
      {needsDefs && !defs && <Loading />}
      {needsDefs && defs && (
        <>
          {tab === "general" && <>{block({ title: "Adresse und Daten", spec: GENERAL })}{block({ title: "Zugang", spec: ACCESS })}{block({ title: "In andere Seiten einbetten", intro: <>So zeigst du NetworkHelper zum Beispiel in Home Assistant an: Dort eine <strong>Webseiten-Karte</strong> oder unter Einstellungen → Dashboards einen <strong>Webseiten-Eintrag</strong> mit der Adresse <code>{window.location.origin}</code> anlegen und die Adresse von Home Assistant hier eintragen. Die Änderung wirkt sofort.</>, spec: EMBED })}</>}
          {tab === "email" && block({
            title: "E-Mail-Warnungen",
            intro: data.smtp_ready ? "E-Mail ist eingerichtet. Warnungen gehen an alle Administratoren, die sie unter Einstellungen nicht abbestellt haben." : "Noch nicht eingerichtet: Warnungen erscheinen nur im Dashboard.",
            spec: EMAIL,
            extra: <TestButton label="Testmail an mich" path="/admin/settings/test-email" describe={(r) => `Gesendet an ${r.to}.`} />,
          })}
          {tab === "email" && block({ title: "Wochenbericht", spec: REPORT, extra: <ReportPreview /> })}
          {tab === "dns" && block({
            title: "Porkbun",
            intro: <>Schlüssel erzeugst du bei Porkbun unter <strong>Account → API Access</strong>. Danach bei jeder Domain unter <strong>Details</strong> „API Access“ einschalten.</>,
            spec: DNS,
            extra: data.porkbun_ready && <TestButton label="Verbindung testen" path="/admin/settings/test-porkbun" describe={(r) => `OK, IP ${r.ip}, Domains: ${r.domains.join(", ") || "keine"}`} />,
          })}
          {tab === "dns" && block({
            title: "AdGuard Home",
            intro: "Optional. NetworkHelper zeigt dann Sperren und Statistik, warnt, wenn Geräte Schadseiten aufrufen wollten oder AdGuard ausfällt, und legt auf Wunsch Umschreibungen für deine eigenen Domains an.",
            spec: ADGUARD,
            extra: data.adguard_ready && <TestButton label="Verbindung testen" path="/admin/settings/test-adguard" describe={(r) => `OK, AdGuard ${r.version}, Schutz ${r.protection ? "an" : "aus"}, ${r.queries} Anfragen.`} />,
          })}
          {tab === "npm" && block({
            title: "Nginx Proxy Manager",
            intro: "NetworkHelper liest die Proxy Hosts (nur lesend). Daraus entstehen Erreichbarkeits-Monitore, Zertifikatsprüfungen und auf Wunsch DNS-Records. Die Zugriffsprotokolle liefert der Agent.",
            spec: NPM,
            extra: data.npm_ready && <TestButton label="Verbindung testen" path="/admin/settings/test-npm" describe={(r) => `OK, ${r.hosts} Proxy Hosts mit ${r.domains} Domains.`} />,
          })}
          {tab === "security" && block({ title: "Sicherheitsüberwachung", spec: SECURITY })}
        </>
      )}
    </>
  );
}
