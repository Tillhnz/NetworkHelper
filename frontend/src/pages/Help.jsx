import { useEffect, useMemo, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { FAQ, GLOSSARY } from "../help.js";
import { useHelp } from "../components/help.jsx";
import HowItWorks from "../components/HowItWorks.jsx";
import { Grade, Pill } from "../components/ui.jsx";

export default function Help({ user }) {
  const { startTour } = useHelp();
  const { hash } = useLocation();
  const [q, setQ] = useState("");
  const entries = useMemo(() => Object.entries(GLOSSARY).sort((a, b) => a[1].title.localeCompare(b[1].title, "de")), []);
  const shown = entries.filter(([, g]) => !q || (g.title + " " + g.text).toLowerCase().includes(q.toLowerCase()));

  useEffect(() => {
    if (!hash) return;
    const el = document.getElementById(hash.slice(1));
    if (el) { el.scrollIntoView({ block: "center" }); el.classList.add("flash"); setTimeout(() => el.classList.remove("flash"), 1800); }
  }, [hash]);

  return (
    <>
      <header className="page-head">
        <h1>Hilfe</h1>
        <div className="actions">
          <button className="btn primary" onClick={startTour}>Tour starten</button>
          {user.role === "admin" && <Link className="btn" to="/setup">Einrichtung öffnen</Link>}
        </div>
      </header>

      <section className="panel">
        <h2>So hängt alles zusammen</h2>
        <p className="muted">
          Ruft jemand <code>cloud.deine-domain.de</code> auf, passiert Folgendes: Porkbun verrät die Adresse deines Anschlusses, dein Router lässt die Anfrage
          durch, der Nginx Proxy Manager schaut auf den Namen und reicht sie an den richtigen Dienst weiter. NetworkHelper sitzt daneben und passt auf.
        </p>
        <HowItWorks />
      </section>

      <section className="panel">
        <h2>Was die Farben bedeuten</h2>
        <ul className="legend-list">
          <li><Pill status="ok" /> Alles gut, nichts zu tun.</li>
          <li><Pill status="warn" /> Verbesserbar oder auffällig. Schau es dir an, wenn du Zeit hast.</li>
          <li><Pill status="crit" /> Bitte bald ansehen: ein Ausfall, eine riskante offene Tür oder ein laufender Angriff.</li>
          <li><Pill status="info" /> Nur zur Info, etwa eine neue öffentliche IP.</li>
          <li><span className="grade-row"><Grade grade="A" /><Grade grade="C" /><Grade grade="F" /></span> Noten für Zertifikat und Sicherheits-Header: A ist bestens, F heißt Handlungsbedarf.</li>
        </ul>
      </section>

      <section className="panel">
        <h2>Was tun, wenn …</h2>
        <div className="faq">
          {FAQ.map((f) => (
            <details key={f.q} className="faq-item">
              <summary>{f.q}</summary>
              <ol>{f.a.map((a) => <li key={a}>{a}</li>)}</ol>
            </details>
          ))}
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Lexikon</h2>
          <input type="search" className="auto" placeholder="Begriff suchen" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Begriff suchen" />
        </div>
        <p className="muted small">Überall in NetworkHelper sind diese Begriffe gepunktet unterstrichen. Ein Klick darauf zeigt die Erklärung direkt an Ort und Stelle.</p>
        <dl className="glossary">
          {shown.map(([k, g]) => (
            <div key={k} id={k} className="glossary-item">
              <dt>{g.title}</dt>
              <dd>{g.text}</dd>
            </div>
          ))}
        </dl>
        {shown.length === 0 && <p className="muted">Kein Begriff gefunden.</p>}
      </section>
    </>
  );
}
