import { Component, useEffect, useRef, useState } from "react";

/* Kleine, App-weite Rückmeldungen: Toasts, Bestätigungsdialog, Lade-Platzhalter und eine Fehlerseite.
   toast() und confirmDialog() sind einfache Funktionen, die man überall aufrufen kann. <FeedbackHost /> sitzt einmal in der App. */

let pushToast = null;
let openConfirm = null;

/** Zeigt eine kurze Meldung. kind: "ok" oder "error". */
export function toast(message, kind = "ok") {
  if (pushToast) pushToast({ message, kind });
}

/** Fragt nach und liefert true oder false. opts: { title, confirmLabel, danger } */
export function confirmDialog(message, opts = {}) {
  if (!openConfirm) return Promise.resolve(window.confirm(message));
  return new Promise((resolve) => openConfirm({ message, ...opts, resolve }));
}

export function FeedbackHost() {
  const [toasts, setToasts] = useState([]);
  const [dlg, setDlg] = useState(null);
  const okRef = useRef(null);
  const lastFocus = useRef(null);

  useEffect(() => {
    let n = 0;
    pushToast = (t) => {
      const id = ++n;
      setToasts((l) => [...l.slice(-3), { ...t, id }]);
      setTimeout(() => setToasts((l) => l.filter((x) => x.id !== id)), t.kind === "error" ? 8000 : 3500);
    };
    openConfirm = (d) => {
      lastFocus.current = document.activeElement;
      setDlg(d);
    };
    return () => { pushToast = null; openConfirm = null; };
  }, []);

  useEffect(() => { if (dlg) okRef.current?.focus(); }, [dlg]);

  function close(answer) {
    dlg?.resolve(answer);
    setDlg(null);
    lastFocus.current?.focus?.();
  }

  function onKey(e) {
    if (e.key === "Escape") { e.stopPropagation(); close(false); }
    if (e.key === "Tab") { // Fokus bleibt im Dialog
      const items = [...e.currentTarget.querySelectorAll("button")];
      const first = items[0], last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  }

  return (
    <>
      <div className="toasts" aria-live="polite" aria-atomic="false">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.kind}`} role={t.kind === "error" ? "alert" : "status"}>{t.message}</div>
        ))}
      </div>
      {dlg && (
        <div className="modal-back" onMouseDown={(e) => { if (e.target === e.currentTarget) close(false); }}>
          <div className="modal" role="alertdialog" aria-modal="true" aria-labelledby="dlg-title" aria-describedby="dlg-text" onKeyDown={onKey}>
            <h3 id="dlg-title">{dlg.title || "Bist du sicher?"}</h3>
            <p id="dlg-text">{dlg.message}</p>
            <div className="actions">
              <button className="btn" onClick={() => close(false)}>Abbrechen</button>
              <button ref={okRef} className={`btn ${dlg.danger === false ? "primary" : "danger-btn"}`} onClick={() => close(true)}>
                {dlg.confirmLabel || "Löschen"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

/** Platzhalter in der Form einer Seite, solange Daten laden. */
export function Loading({ rows = 3 }) {
  return (
    <div className="skeleton" role="status" aria-label="Lade …">
      <div className="sk sk-title" />
      {Array.from({ length: rows }, (_, i) => <div key={i} className="sk sk-block" />)}
    </div>
  );
}

/** Fängt Darstellungsfehler ab, damit nicht die ganze Seite weiß bleibt. */
export class ErrorBoundary extends Component {
  state = { error: null };
  static getDerivedStateFromError(error) { return { error }; }
  componentDidCatch(error) { console.error(error); }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="center">
        <div className="empty" role="alert">
          <h3>Hier ist etwas schiefgegangen</h3>
          <p className="muted">Die Seite konnte nicht angezeigt werden. Deine Daten sind nicht betroffen.</p>
          <div className="actions">
            <button className="btn primary" onClick={() => window.location.reload()}>Seite neu laden</button>
            <a className="btn" href="/">Zur Startseite</a>
          </div>
        </div>
      </div>
    );
  }
}
