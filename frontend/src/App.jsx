import { useCallback, useEffect, useRef, useState } from "react";
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { api, logoutRequest, migrateLegacySession, setUnauthorizedHandler } from "./api.js";
import Shell from "./components/Shell.jsx";
import { ErrorBoundary, FeedbackHost } from "./components/feedback.jsx";
import { HelpProvider } from "./components/help.jsx";
import { TwoFactorGate } from "./components/TwoFactor.jsx";
import Access from "./pages/Access.jsx";
import Admin from "./pages/Admin.jsx";
import Alerts from "./pages/Alerts.jsx";
import Connections from "./pages/Connections.jsx";
import Dns from "./pages/Dns.jsx";
import Help from "./pages/Help.jsx";
import Login from "./pages/Login.jsx";
import Overview from "./pages/Overview.jsx";
import Security from "./pages/Security.jsx";
import Settings from "./pages/Settings.jsx";
import Setup from "./pages/Setup.jsx";
import Uptime from "./pages/Uptime.jsx";

export default function App() {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [user, setUser] = useState(null);
  const sentToSetup = useRef(false);
  const [loading, setLoading] = useState(true);

  const logout = useCallback(async () => {
    await logoutRequest();
    setUser(null);
    navigate("/login");
  }, [navigate]);

  const loadUser = useCallback(async () => {
    try {
      setUser(await api.get("/me"));
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUser(null);
      navigate("/login");
    });
    migrateLegacySession().then(loadUser);
  }, [loadUser, navigate]);

  // Beim ersten Anmelden führt der Assistent Administratoren durch die Einrichtung
  useEffect(() => {
    if (user?.role === "admin" && !user.must_setup_2fa && !user.onboarding_done && !sentToSetup.current && pathname !== "/setup") {
      sentToSetup.current = true;
      navigate("/setup");
    }
  }, [user, pathname, navigate]);

  if (loading) return <div className="center muted">Lade …</div>;

  if (!user) {
    return (
      <>
        <FeedbackHost />
        <Routes>
          <Route path="/login" element={<Login onLoggedIn={loadUser} />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </>
    );
  }

  if (user.must_setup_2fa) {
    return (
      <>
        <FeedbackHost />
        <TwoFactorGate user={user} onDone={loadUser} onLogout={logout} />
      </>
    );
  }

  return (
    <HelpProvider user={user} onUser={setUser}>
    <Shell user={user} onLogout={logout}>
      <FeedbackHost />
      <ErrorBoundary>
        <Routes>
          <Route path="/" element={<Overview user={user} />} />
          <Route path="/access" element={<Access user={user} />} />
          <Route path="/connections" element={<Connections user={user} />} />
          <Route path="/security" element={<Security user={user} />} />
          <Route path="/uptime" element={<Uptime user={user} />} />
          <Route path="/dns" element={<Dns user={user} />} />
          <Route path="/alerts" element={<Alerts user={user} />} />
          <Route path="/help" element={<Help user={user} />} />
          {user.role === "admin" && <Route path="/setup" element={<Setup />} />}
          {user.role === "admin" && <Route path="/admin" element={<Admin user={user} />} />}
          <Route path="/settings" element={<Settings user={user} onChange={setUser} onLogout={logout} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </ErrorBoundary>
    </Shell>
    </HelpProvider>
  );
}
