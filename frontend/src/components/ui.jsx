import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { countryName, flag, SEVERITY } from "../api.js";

export function EmptyState({ title, text, children }) {
  return (
    <div className="empty">
      <h3>{title}</h3>
      {text && <p className="muted">{text}</p>}
      {children}
    </div>
  );
}

export function Kpi({ value, unit, label, tone, sub, to }) {
  const body = (
    <>
      <div className={`kpi-value ${tone ? `tone-${tone}` : ""}`}>{value}{unit && <small>{unit}</small>}</div>
      <div className="kpi-label">{label}</div>
      {sub && <div className="kpi-sub">{sub}</div>}
    </>
  );
  return to ? <Link className="kpi kpi-link" to={to}>{body}</Link> : <div className="kpi">{body}</div>;
}

const PILL_TEXT = {
  ok: "In Ordnung", up: "Erreichbar", down: "Ausgefallen", unknown: "Unbekannt", paused: "Pausiert",
  info: SEVERITY.info, warn: SEVERITY.warn, crit: SEVERITY.crit, online: "Online", offline: "Offline",
};
const PILL_TONE = { ok: "ok", up: "ok", online: "ok", down: "due", crit: "due", offline: "due", warn: "soon", info: "muted", unknown: "unknown", paused: "unknown" };

export function Pill({ status, children, tone }) {
  return <span className={`pill pill-${tone || PILL_TONE[status] || "muted"}`}>{children ?? PILL_TEXT[status] ?? status}</span>;
}

/** Statuspunkt, der bei „aktiv“ leise pulsiert. */
export function Dot({ tone = "ok", pulse = false, label }) {
  return <span className={`dot dot-${tone} ${pulse ? "pulse" : ""}`} role={label ? "img" : undefined} aria-label={label} aria-hidden={label ? undefined : true} />;
}

export function Country({ code, org, compact = false }) {
  const name = org === "Heimnetz" ? "Heimnetz" : countryName(code);
  return (
    <span className="country" title={org && org !== "Heimnetz" ? `${name} · ${org}` : name}>
      <span className="flag" aria-hidden="true">{org === "Heimnetz" ? "🏠" : flag(code)}</span>
      {!compact && <span>{name}</span>}
    </span>
  );
}

export function Grade({ grade }) {
  if (!grade) return <span className="grade grade-none">–</span>;
  return <span className={`grade grade-${grade}`} aria-label={`Note ${grade}`}>{grade}</span>;
}

/** Ringanzeige 0–100 für den Sicherheitsstatus. */
export function ScoreRing({ score, level, size = 132 }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const [shown, setShown] = useState(0);
  useEffect(() => { const id = requestAnimationFrame(() => setShown(score)); return () => cancelAnimationFrame(id); }, [score]);
  return (
    <svg viewBox="0 0 120 120" width={size} height={size} className={`score-ring score-${level}`} role="img" aria-label={`Sicherheitsstatus ${score} von 100`}>
      <circle cx="60" cy="60" r={r} className="score-track" />
      {Array.from({ length: 40 }, (_, i) => (
        <line key={i} x1="60" y1="2" x2="60" y2={i % 5 === 0 ? 9 : 6} className="score-tick" transform={`rotate(${i * 9} 60 60)`} />
      ))}
      <circle cx="60" cy="60" r={r} className="score-fill" strokeDasharray={c} strokeDashoffset={c * (1 - shown / 100)} transform="rotate(-90 60 60)" />
      <text x="60" y="66" textAnchor="middle" className="score-num">{score}</text>
      <text x="60" y="84" textAnchor="middle" className="score-of">von 100</text>
    </svg>
  );
}

/** Zahl, die beim ersten Anzeigen hochzählt. */
export function CountUp({ value, format = (v) => v }) {
  const [shown, setShown] = useState(0);
  const from = useRef(0);
  useEffect(() => {
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches || !value) { setShown(value || 0); return undefined; }
    const start = performance.now();
    const a = from.current;
    let id;
    const step = (t) => {
      const k = Math.min(1, (t - start) / 700);
      const v = a + (value - a) * (1 - Math.pow(1 - k, 3));
      setShown(k < 1 ? v : value);
      if (k < 1) id = requestAnimationFrame(step);
      else from.current = value;
    };
    id = requestAnimationFrame(step);
    return () => cancelAnimationFrame(id);
  }, [value]);
  return <>{format(Math.round(shown))}</>;
}

/** Seitliche Schublade für Details (zum Beispiel zu einer IP-Adresse). */
export function Drawer({ title, onClose, children }) {
  const ref = useRef(null);
  useEffect(() => {
    const last = document.activeElement;
    ref.current?.focus();
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("keydown", onKey); last?.focus?.(); };
  }, [onClose]);
  return (
    <div className="drawer-back" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} ref={ref}>
        <header className="drawer-head">
          <h2>{title}</h2>
          <button className="btn small" onClick={onClose} aria-label="Schließen">Schließen</button>
        </header>
        <div className="drawer-body">{children}</div>
      </aside>
    </div>
  );
}

/** Code-Zeile mit Knopf zum Kopieren. */
export function CopyLine({ text }) {
  const [done, setDone] = useState(false);
  return (
    <div className="copy-line">
      <code>{text}</code>
      <button className="btn small" type="button" onClick={async () => {
        try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1800); } catch { /* ohne Zwischenablage */ }
      }}>{done ? "Kopiert" : "Kopieren"}</button>
    </div>
  );
}

export function usePoll(fn, ms, deps = []) {
  useEffect(() => {
    fn();
    const id = setInterval(() => { if (document.visibilityState === "visible") fn(); }, ms);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}
