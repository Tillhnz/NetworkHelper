import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, setToken } from "../api.js";
import ThemeToggle from "../components/ThemeToggle.jsx";

export default function Login({ onLoggedIn }) {
  const navigate = useNavigate();
  const inviteParam = new URLSearchParams(window.location.search).get("invite") || "";
  const [mode, setMode] = useState(inviteParam ? "register" : "login");
  const [allowRegistration, setAllowRegistration] = useState(true);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [invite, setInvite] = useState(inviteParam);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => { api.get("/config").then((c) => setAllowRegistration(c.allow_registration)).catch(() => {}); }, []);

  async function submit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const path = mode === "login" ? "/auth/login" : "/auth/register";
      const body = mode === "login" ? { email, password } : { email, password, invite: invite.trim() || null };
      const { access_token } = await api.post(path, body);
      setToken(access_token);
      await onLoggedIn();
      navigate("/");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <ThemeToggle className="theme-toggle-corner" />
      <div className="login-art" aria-hidden="true">
        <div className="login-radar">
          <span className="ring r1" /><span className="ring r2" /><span className="ring r3" />
          <span className="sweep" />
          <span className="blip b1" /><span className="blip b2" /><span className="blip b3" />
        </div>
        <div className="login-km"><span>4</span><span>4</span><span>3</span></div>
        <p>Zugriffe, Sicherheit und DNS für die Dienste auf deinem Server, an einem Ort.</p>
      </div>
      <form className="login-form" onSubmit={submit}>
        <h1>{mode === "login" ? "Anmelden" : "Konto anlegen"}</h1>
        <label>
          E-Mail
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus autoComplete="email" />
        </label>
        <label>
          Passwort
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} minLength={mode === "register" ? 8 : undefined}
                 autoComplete={mode === "login" ? "current-password" : "new-password"} required />
          {mode === "register" && <span className="hint">Mindestens 8 Zeichen. Das erste Konto wird Administrator.</span>}
        </label>
        {mode === "register" && !allowRegistration && (
          <label>
            Einladungscode
            <input value={invite} onChange={(e) => setInvite(e.target.value)} maxLength={32} autoComplete="off" />
            <span className="hint">Die Registrierung ist geschlossen. Den Code bekommst du vom Administrator.</span>
          </label>
        )}
        {error && <p className="error" role="alert">{error}</p>}
        <button className="btn primary" disabled={busy}>{mode === "login" ? "Anmelden" : "Konto anlegen"}</button>
        <button type="button" className="link" onClick={() => { setMode(mode === "login" ? "register" : "login"); setError(""); }}>
          {mode === "login" ? "Noch kein Konto? Konto anlegen" : "Schon ein Konto? Anmelden"}
        </button>
      </form>
    </div>
  );
}
