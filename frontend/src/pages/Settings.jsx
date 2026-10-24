import { useState } from "react";
import { api, setToken } from "../api.js";
import { Segmented, Switch } from "../components/controls.jsx";
import { toast } from "../components/feedback.jsx";
import { getTheme, setTheme } from "../theme.js";

export default function Settings({ user, onChange }) {
  const [theme, setLocalTheme] = useState(getTheme());
  const [pw, setPw] = useState({ current_password: "", new_password: "" });
  const [error, setError] = useState("");

  async function alerts(v) {
    try { onChange(await api.put("/me/alerts", { alert_email: v })); toast(v ? "Du bekommst Warnungen per E-Mail." : "Keine Warnungen mehr per E-Mail."); } catch (e) { toast(e.message, "error"); }
  }
  async function changePw(e) {
    e.preventDefault();
    setError("");
    try {
      const r = await api.put("/auth/password", pw);
      setToken(r.access_token);
      setPw({ current_password: "", new_password: "" });
      toast("Passwort geändert. Andere Geräte sind abgemeldet.");
    } catch (err) { setError(err.message); }
  }
  async function logoutAll() {
    try { const r = await api.post("/auth/logout-all", {}); setToken(r.access_token); toast("Alle anderen Geräte sind abgemeldet."); } catch (e) { toast(e.message, "error"); }
  }

  return (
    <>
      <header className="page-head"><h1>Einstellungen</h1></header>
      <section className="panel">
        <h2>Konto</h2>
        <p>Angemeldet als <strong>{user.email}</strong> ({user.role === "admin" ? "Administrator" : "Nutzer"}).</p>
        <Switch checked={user.alert_email} onChange={alerts}>Warnungen per E-Mail an diese Adresse</Switch>
        <p className="muted small">Ob und ab welcher Stufe gemailt wird, legt der Administrator unter Administration → E-Mail fest.</p>
      </section>
      <section className="panel">
        <h2>Darstellung</h2>
        <Segmented value={theme} onChange={(v) => { setTheme(v); setLocalTheme(v); }}
                   options={[{ value: "auto", label: "Wie das Gerät" }, { value: "light", label: "Hell" }, { value: "dark", label: "Dunkel" }]} />
      </section>
      <section className="panel">
        <h2>Sicherheit</h2>
        <form className="form-grid" onSubmit={changePw}>
          <label>Aktuelles Passwort<input type="password" value={pw.current_password} onChange={(e) => setPw({ ...pw, current_password: e.target.value })} autoComplete="current-password" required /></label>
          <label>Neues Passwort<input type="password" value={pw.new_password} onChange={(e) => setPw({ ...pw, new_password: e.target.value })} minLength={8} autoComplete="new-password" required /></label>
          {error && <p className="error span-all">{error}</p>}
          <div className="actions span-all">
            <button className="btn primary">Passwort ändern</button>
            <button type="button" className="btn" onClick={logoutAll}>Alle anderen Geräte abmelden</button>
          </div>
        </form>
      </section>
    </>
  );
}
