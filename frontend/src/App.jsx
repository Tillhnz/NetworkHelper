import { useCallback, useEffect, useState } from "react";
import { Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { api, clearToken, getToken, setUnauthorizedHandler } from "./api.js";
import Shell from "./components/Shell.jsx";
import { ErrorBoundary, FeedbackHost } from "./components/feedback.jsx";
import Access from "./pages/Access.jsx";
import Admin from "./pages/Admin.jsx";
import Alerts from "./pages/Alerts.jsx";
import Connections from "./pages/Connections.jsx";
import Dns from "./pages/Dns.jsx";
import Login from "./pages/Login.jsx";
import Overview from "./pages/Overview.jsx";
import Security from "./pages/Security.jsx";
import Settings from "./pages/Settings.jsx";
import Uptime from "./pages/Uptime.jsx";

export default function App() {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(!!getToken());

  const logout = useCallback(() => {
    clearToken();
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
    if (getToken()) loadUser();
  }, [loadUser, navigate]);

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

  return (
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
          {user.role === "admin" && <Route path="/admin" element={<Admin user={user} />} />}
          <Route path="/settings" element={<Settings user={user} onChange={setUser} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </ErrorBoundary>
    </Shell>
  );
}
