import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { api } from "../api.js";
import { GLOSSARY, INTROS, TOUR } from "../help.js";

/* Einführung: Kontext mit Konto und Tour, anklickbare Begriffe, Seiten-Einführungen und die geführte Tour. */

const HelpCtx = createContext({ user: null, hidden: [], hideHint: () => {}, startTour: () => {} });
export const useHelp = () => useContext(HelpCtx);

export function HelpProvider({ user, onUser, children }) {
  const [tour, setTour] = useState(null); // Index des aktuellen Schritts oder null
  const hideHint = useCallback(async (id) => {
    onUser({ ...user, hints_hidden: [...(user.hints_hidden || []), id] });
    try { onUser(await api.put("/me/onboarding", { hide_hint: id })); } catch { /* bleibt lokal ausgeblendet */ }
  }, [user, onUser]);
  const finishTour = useCallback(async () => {
    setTour(null);
    if (!user.tour_done) {
      try { onUser(await api.put("/me/onboarding", { tour_done: true })); } catch { /* nicht schlimm */ }
    }
  }, [user, onUser]);
  const value = { user, hidden: user.hints_hidden || [], hideHint, startTour: () => setTour(0), onUser };
  return (
    <HelpCtx.Provider value={value}>
      {children}
      {tour !== null && <Tour step={tour} setStep={setTour} onDone={finishTour} isAdmin={user.role === "admin"} />}
    </HelpCtx.Provider>
  );
}

// ---------- Kleine Erklärkarte an einem Element ----------

function Popover({ anchor, onClose, children }) {
  const ref = useRef(null);
  const [pos, setPos] = useState(null);
  useLayoutEffect(() => {
    const place = () => {
      const r = anchor.getBoundingClientRect();
      const w = Math.min(340, window.innerWidth - 24);
      const left = Math.max(12, Math.min(r.left + r.width / 2 - w / 2, window.innerWidth - w - 12));
      const h = ref.current?.offsetHeight || 160;
      const below = r.bottom + 10 + h < window.innerHeight;
      setPos({ left, width: w, top: below ? r.bottom + 10 : Math.max(12, r.top - h - 10) });
    };
    place();
    window.addEventListener("resize", place);
    window.addEventListener("scroll", place, true);
    return () => { window.removeEventListener("resize", place); window.removeEventListener("scroll", place, true); };
  }, [anchor]);
  useEffect(() => {
    const onDown = (e) => { if (!ref.current?.contains(e.target) && !anchor.contains(e.target)) onClose(); };
    const onKey = (e) => { if (e.key === "Escape") { onClose(); anchor.focus(); } };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onDown); document.removeEventListener("keydown", onKey); };
  }, [anchor, onClose]);
  return (
    <div ref={ref} className="popover" role="dialog" style={pos ? { left: pos.left, top: pos.top, width: pos.width } : { visibility: "hidden" }}>
      {children}
    </div>
  );
}

function GlossaryCard({ k, onClose }) {
  const g = GLOSSARY[k];
  if (!g) return null;
  return (
    <>
      <strong className="popover-title">{g.title}</strong>
      <p>{g.text}</p>
      <Link className="link small" to={`/help#${k}`} onClick={onClose}>Im Lexikon ansehen</Link>
    </>
  );
}

/** Fachbegriff mit gepunkteter Linie; ein Klick erklärt ihn. */
export function Term({ k, children }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  return (
    <>
      <button type="button" ref={ref} className="term" onClick={() => setOpen(!open)} aria-expanded={open}>
        {children ?? GLOSSARY[k]?.title}
      </button>
      {open && <Popover anchor={ref.current} onClose={() => setOpen(false)}><GlossaryCard k={k} onClose={() => setOpen(false)} /></Popover>}
    </>
  );
}

/** Kleines Fragezeichen neben einer Überschrift. Mit k ein Lexikon-Eintrag, sonst eigener Text. */
export function InfoTip({ k, title, children, label = "Was ist das?" }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  return (
    <>
      <button type="button" ref={ref} className="info-tip" onClick={() => setOpen(!open)} aria-label={label} aria-expanded={open} title={label}>?</button>
      {open && (
        <Popover anchor={ref.current} onClose={() => setOpen(false)}>
          {k ? <GlossaryCard k={k} onClose={() => setOpen(false)} /> : <>{title && <strong className="popover-title">{title}</strong>}<div className="popover-text">{children}</div></>}
        </Popover>
      )}
    </>
  );
}

/** Einführung oben auf einer Seite, lässt sich ausblenden (pro Konto gemerkt). */
export function PageIntro({ id, children }) {
  const { hidden, hideHint } = useHelp();
  const intro = INTROS[id];
  if (!intro || hidden.includes(`intro:${id}`)) return null;
  return (
    <aside className="page-intro" aria-label="Kurze Erklärung">
      <span className="page-intro-icon" aria-hidden="true">i</span>
      <div className="grow">
        <strong>{intro.title}</strong>
        <p>{intro.text}</p>
        {children}
      </div>
      <button className="btn small" onClick={() => hideHint(`intro:${id}`)}>Verstanden</button>
    </aside>
  );
}

// ---------- Geführte Tour ----------

function Tour({ step, setStep, onDone, isAdmin }) {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const steps = TOUR.filter((s) => !s.admin || isAdmin);
  const s = steps[step];
  const [rect, setRect] = useState(null);
  const [ready, setReady] = useState(false);
  const cardRef = useRef(null);
  const [cardPos, setCardPos] = useState(null);
  const [atTop, setAtTop] = useState(false); // Handy: Karte oben, wenn das Ziel unten liegt (etwa das Menü)

  // Zur Seite des Schritts wechseln und auf das Element warten
  useEffect(() => {
    if (!s) return undefined;
    setReady(false);
    setRect(null);
    if (pathname !== s.path) { navigate(s.path); return undefined; }
    let tries = 0;
    let el = null;
    const id = setInterval(() => {
      tries += 1;
      el = s.target ? [...document.querySelectorAll(`[data-tour="${s.target}"]`)].find((e) => e.getClientRects().length) : null;
      if (el || !s.target || tries > 25) {
        clearInterval(id);
        if (el) {
          el.scrollIntoView({ block: window.innerWidth < 700 ? "start" : "center", behavior: window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
          setTimeout(() => { setRect(el.getBoundingClientRect()); setReady(true); }, 350);
        } else {
          setReady(true);
        }
      }
    }, 80);
    const update = () => { if (el) setRect(el.getBoundingClientRect()); };
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, true);
    return () => { clearInterval(id); window.removeEventListener("resize", update); window.removeEventListener("scroll", update, true); };
  }, [s, pathname, navigate]);

  // Karte neben dem markierten Bereich platzieren (auf dem Handy immer unten)
  useLayoutEffect(() => {
    if (!ready) return;
    const card = cardRef.current;
    if (!card) return;
    const w = card.offsetWidth, h = card.offsetHeight, vw = window.innerWidth, vh = window.innerHeight;
    if (!rect || vw < 700) { setCardPos(null); setAtTop(!!rect && rect.top + rect.height / 2 > vh / 2); return; }
    let top = rect.bottom + 14;
    if (top + h > vh - 12) top = rect.top - h - 14;
    if (top < 12) top = Math.min(vh - h - 12, Math.max(12, rect.top + 12));
    let left = rect.left;
    if (rect.right + w + 20 < vw && rect.height > vh * 0.45) { left = rect.right + 16; top = Math.max(12, Math.min(rect.top, vh - h - 12)); }
    left = Math.max(12, Math.min(left, vw - w - 12));
    setCardPos({ top, left });
  }, [ready, rect, step]);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") onDone();
      if (e.key === "ArrowRight") setStep((i) => (i < steps.length - 1 ? i + 1 : i));
      if (e.key === "ArrowLeft") setStep((i) => Math.max(0, i - 1));
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onDone, setStep, steps.length]);

  useEffect(() => { if (ready) cardRef.current?.querySelector(".btn.primary")?.focus(); }, [ready, step]);

  if (!s) return null;
  const last = step === steps.length - 1;
  const pad = 6;
  return (
    <div className="tour" role="dialog" aria-modal="true" aria-labelledby="tour-title">
      {rect && ready ? (
        <div className="tour-hole" style={{ top: rect.top - pad, left: rect.left - pad, width: rect.width + pad * 2, height: rect.height + pad * 2 }} />
      ) : <div className="tour-dim" />}
      <div ref={cardRef} className={`tour-card ${cardPos ? "" : "is-floating"} ${atTop ? "at-top" : ""} ${ready ? "" : "is-waiting"}`} style={cardPos || undefined}>
        <div className="tour-progress" aria-hidden="true">
          {steps.map((_, i) => <span key={i} className={i <= step ? "on" : ""} />)}
        </div>
        <span className="eyebrow">Schritt {step + 1} von {steps.length}</span>
        <h3 id="tour-title">{s.title}</h3>
        <p>{s.text}</p>
        <div className="tour-actions">
          {!last && <button className="link small" onClick={onDone}>Tour beenden</button>}
          <span className="grow" />
          {step > 0 && <button className="btn small" onClick={() => setStep(step - 1)}>Zurück</button>}
          <button className="btn primary small" onClick={() => (last ? onDone() : setStep(step + 1))}>{last ? "Fertig" : "Weiter"}</button>
        </div>
      </div>
    </div>
  );
}
