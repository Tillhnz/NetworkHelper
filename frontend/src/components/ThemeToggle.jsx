import { useEffect, useState } from "react";
import { effectiveTheme, setTheme } from "../theme.js";

/** Schalter für helle und dunkle Darstellung, gedacht für die obere Ecke. */
export default function ThemeToggle({ className = "" }) {
  const [theme, setLocal] = useState(effectiveTheme());
  useEffect(() => {
    const sync = () => setLocal(effectiveTheme());
    window.addEventListener("themechange", sync);
    return () => window.removeEventListener("themechange", sync);
  }, []);
  const toLight = theme === "dark";
  return (
    <button
      type="button"
      className={`theme-toggle ${className}`}
      onClick={() => setTheme(toLight ? "light" : "dark")}
      aria-label={toLight ? "Zur hellen Darstellung wechseln" : "Zur dunklen Darstellung wechseln"}
      title={toLight ? "Hell" : "Dunkel"}
    >
      <svg viewBox="0 0 24 24" className="nav-icon" aria-hidden="true" focusable="false">
        {toLight
          ? <path d="M12 8 A4 4 0 1 0 12.01 8 M12 2 V4 M12 20 V22 M2 12 H4 M20 12 H22 M4.9 4.9 L6.3 6.3 M17.7 17.7 L19.1 19.1 M4.9 19.1 L6.3 17.7 M17.7 6.3 L19.1 4.9" />
          : <path d="M20 14.5 A8 8 0 1 1 9.5 4 A6.5 6.5 0 0 0 20 14.5 Z" />}
      </svg>
    </button>
  );
}
