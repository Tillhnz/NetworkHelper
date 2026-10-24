import { useState } from "react";

/** Klickweg wie „Internet › Freigaben › Portfreigaben“. */
export function MenuPath({ path }) {
  return (
    <span className="menu-path" aria-label={`Menü: ${path.join(", dann ")}`}>
      {path.map((p, i) => <span key={i}><span className="menu-step">{p}</span>{i < path.length - 1 && <span className="menu-sep" aria-hidden="true">›</span>}</span>)}
    </span>
  );
}

/** Eine Anleitung: warum, Klickweg, Schritte. Optional mit Haken für die Checkliste. */
export function GuideCard({ guide, open: initial = false, done, onToggleDone }) {
  const [open, setOpen] = useState(initial);
  return (
    <div className={`guide ${open ? "is-open" : ""} ${done ? "is-done" : ""}`}>
      <div className="guide-head">
        {onToggleDone && (
          <button type="button" className={`guide-check ${done ? "on" : ""}`} onClick={onToggleDone}
                  aria-pressed={!!done} aria-label={done ? `„${guide.title}“ als offen markieren` : `„${guide.title}“ als erledigt markieren`}>
            {done ? "✓" : ""}
          </button>
        )}
        <button type="button" className="guide-title" onClick={() => setOpen(!open)} aria-expanded={open}>
          <strong>{guide.title}</strong>
          <span className="guide-chevron" aria-hidden="true">{open ? "−" : "+"}</span>
        </button>
      </div>
      {open && (
        <div className="guide-body">
          <p className="muted">{guide.why}</p>
          <MenuPath path={guide.path} />
          <ol className="guide-steps">{guide.steps.map((s) => <li key={s}>{s}</li>)}</ol>
        </div>
      )}
    </div>
  );
}
