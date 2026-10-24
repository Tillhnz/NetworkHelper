import { useEffect } from "react";
import { NavLink, useLocation } from "react-router-dom";
import ThemeToggle from "./ThemeToggle.jsx";

const NAV = [
  { to: "/", label: "Übersicht", short: "Start", end: true, icon: "M4 13 A8 8 0 0 1 20 13 M12 13 L16 8.5 M6 19 H18" },
  { to: "/access", label: "Zugriffe", icon: "M3 17 L8 11 L12 14 L17 7 L21 10 M3 21 H21" },
  { to: "/connections", label: "Verbindungen", short: "Server", icon: "M5 5 H19 V10 H5 Z M5 14 H19 V19 H5 Z M8 7.5 H8.01 M8 16.5 H8.01" },
  { to: "/security", label: "Sicherheit", icon: "M12 3 L19 6 V11 C19 15.5 16 19 12 21 C8 19 5 15.5 5 11 V6 Z M9 12 L11 14 L15 10" },
  { to: "/uptime", label: "Erreichbarkeit", short: "Status", icon: "M3 12 H7 L9 7 L13 17 L15 12 H21" },
  { to: "/dns", label: "DNS", icon: "M12 3 A9 9 0 1 0 12.01 3 M3 12 H21 M12 3 C9 6 9 18 12 21 M12 3 C15 6 15 18 12 21" },
  { to: "/settings", label: "Einstellungen", short: "Konto", icon: "M12 9 A3 3 0 1 0 12.01 9 M12 3 V5 M12 19 V21 M3 12 H5 M19 12 H21 M5.6 5.6 L7 7 M17 17 L18.4 18.4 M18.4 5.6 L17 7 M7 17 L5.6 18.4" },
];

/** Rahmen der App: Seitenleiste am Computer, schmale Kopfzeile und Tabs am unteren Rand auf dem Handy. */
export default function Shell({ user, onLogout, children }) {
  const { pathname } = useLocation();
  useEffect(() => {
    const hit = [...NAV].reverse().find((n) => (n.end ? pathname === n.to : pathname.startsWith(n.to)));
    const extra = { "/admin": "Administration", "/alerts": "Meldungen", "/help": "Hilfe", "/setup": "Einrichtung" }[pathname];
    document.title = extra ? `${extra} · NetworkHelper` : hit ? `${hit.label} · NetworkHelper` : "NetworkHelper";
  }, [pathname]);
  return (
    <div className="shell">
      <a className="skip-link" href="#inhalt">Zum Inhalt springen</a>
      <aside className="sidebar">
        <div className="brand-row">
          <div className="brand">
            <span className="brand-mark" aria-hidden="true"><span /></span>
            NetworkHelper
          </div>
          <ThemeToggle />
        </div>
        <nav aria-label="Hauptmenü" data-tour="nav">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end}>
              <svg viewBox="0 0 24 24" className="nav-icon" aria-hidden="true" focusable="false"><path d={n.icon} /></svg>
              <span className="nav-label">{n.label}</span>
              {n.short && <span className="nav-short" aria-hidden="true">{n.short}</span>}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span className="muted small">{user.email}</span>
          <NavLink className="link foot-alerts" to="/alerts" data-tour="alerts-link">Meldungen</NavLink>
          <NavLink className="link" to="/help" data-tour="help-link">Hilfe</NavLink>
          {user.role === "admin" && <NavLink className="link" to="/admin"><span className="nav-foot-long">Administration</span><span className="nav-foot-short">Admin</span></NavLink>}
          <button className="link foot-logout" onClick={onLogout}>Abmelden</button>
        </div>
      </aside>
      <main className="main" id="inhalt" tabIndex={-1}>
        <div className="page" key={pathname}>{children}</div>
      </main>
    </div>
  );
}
