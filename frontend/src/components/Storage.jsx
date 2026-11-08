import { useCallback, useEffect, useState } from "react";
import { api, fmtAgo, fmtBytes, fmtNum } from "../api.js";
import { Loading, toast } from "./feedback.jsx";

const DOCKER = { Images: "Docker-Images", "Build Cache": "Bau-Zwischenstände", "Local Volumes": "Daten-Volumes", Containers: "Container" };

/** Speicherplatz: Datenbank, Docker, Sicherungen – und aufräumen. */
export default function Storage() {
  const [d, setD] = useState(null);
  const [busy, setBusy] = useState("");
  const [ret, setRet] = useState(null);
  const load = useCallback(() => api.get("/admin/storage").then((x) => { setD(x); setRet((r) => r ?? { days: x.db.retention_days, blocked: x.db.retention_blocked_days }); }).catch((e) => toast(e.message, "error")), []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!d?.shrink?.running) return undefined;
    const id = setInterval(load, 4000);
    return () => clearInterval(id);
  }, [d?.shrink?.running, load]);

  async function cleanup() {
    setBusy("cleanup");
    try { const r = await api.post("/admin/storage/cleanup", {}); toast("Aufgeräumt. " + r.log.join(" · ")); load(); } catch (e) { toast(e.message, "error"); } finally { setBusy(""); }
  }
  async function shrink() {
    try { await api.post("/admin/storage/shrink", {}); toast("Datenbank wird verkleinert. Das kann einige Minuten dauern."); load(); } catch (e) { toast(e.message, "error"); }
  }
  async function saveRetention() {
    setBusy("ret");
    try {
      await api.put("/admin/settings", { values: { retention_days: Number(ret.days), retention_blocked_days: Number(ret.blocked) } });
      toast("Gespeichert. Mit „Datenbank verkleinern“ wird der Platz sofort frei.");
      load();
    } catch (e) { toast(e.message, "error"); } finally { setBusy(""); }
  }
  if (!d) return <section className="panel"><h2>Speicherplatz</h2><Loading rows={2} /></section>;
  const disk = d.disk;
  const reclaim = disk ? disk.docker.filter((x) => x.type === "Images" || x.type === "Build Cache").reduce((a, x) => a + (x.reclaimable || 0), 0) : 0;
  const used = disk ? disk.disk_total - disk.disk_free : 0;
  return (
    <section className="panel">
      <h2>Speicherplatz</h2>
      {disk && (
        <>
          <div className="meter" role="img" aria-label={`${fmtBytes(used)} von ${fmtBytes(disk.disk_total)} belegt`}>
            <span style={{ width: `${Math.min(100, (100 * used) / disk.disk_total)}%` }} />
          </div>
          <p className="small">{fmtBytes(used)} von {fmtBytes(disk.disk_total)} belegt, <strong>{fmtBytes(disk.disk_free)} frei</strong>.</p>
        </>
      )}
      <table className="rows small storage-table">
        <tbody>
          <tr><td>Datenbank</td><td className="num">{fmtBytes(d.db.total)}</td></tr>
          {disk && disk.docker.map((x) => (
            <tr key={x.type}><td>{DOCKER[x.type] || x.type}{x.reclaimable > 0 && x.type !== "Local Volumes" && <span className="muted"> · davon {fmtBytes(x.reclaimable)} unnötig</span>}</td><td className="num">{fmtBytes(x.size)}</td></tr>
          ))}
          {disk && <tr><td>Sicherungen der Datenbank</td><td className="num">{fmtBytes(disk.backups)}</td></tr>}
        </tbody>
      </table>
      {d.disk_error && <p className="small tone-warn">{d.disk_error}</p>}
      {disk && (
        <p>
          <button className="btn primary" onClick={cleanup} disabled={busy === "cleanup"}>{busy === "cleanup" ? "Räume auf …" : `Alte Images aufräumen${reclaim ? ` (bis zu ${fmtBytes(reclaim)})` : ""}`}</button>{" "}
          <span className="muted small">Nach jedem Update bleibt die alte Version als Image liegen. Laufende Dienste und deine Daten bleiben unberührt. Passiert ab jetzt nach jedem Update von selbst.</span>
        </p>
      )}

      <h3 className="sub-title">Datenbank</h3>
      <table className="rows small storage-table">
        <tbody>
          {d.db.tables.slice(0, 6).map((t) => <tr key={t.name}><td>{t.label}</td><td className="num">{fmtBytes(t.size)}</td></tr>)}
        </tbody>
      </table>
      <p className="small muted">Zurzeit kommen etwa {fmtNum(d.db.access_per_day)} Zugriffe pro Tag dazu, davon {fmtNum(d.db.blocked_per_day)} abgewiesene (Sperrliste, Länder). Die meisten sind Bots.</p>
      {ret && (
        <div className="inline-form">
          <label>Zugriffe aufheben (Tage)<input type="number" min="1" max="400" value={ret.days} onChange={(e) => setRet({ ...ret, days: e.target.value })} /></label>
          <label>Abgewiesene aufheben (Tage)<input type="number" min="1" max="400" value={ret.blocked} onChange={(e) => setRet({ ...ret, blocked: e.target.value })} /></label>
          <button className="btn" onClick={saveRetention} disabled={busy === "ret" || (Number(ret.days) === d.db.retention_days && Number(ret.blocked) === d.db.retention_blocked_days)}>Speichern</button>
        </div>
      )}
      <p>
        <button className="btn" onClick={shrink} disabled={d.shrink.running}>{d.shrink.running ? "Verkleinere …" : "Datenbank verkleinern"}</button>{" "}
        <span className="muted small">
          {d.shrink.finished && !d.shrink.running ? (d.shrink.error ? `Fehler: ${d.shrink.error}` : `Zuletzt ${fmtAgo(d.shrink.finished)}: ${fmtBytes(d.shrink.freed)} frei geworden. `) : ""}
          Gelöschte Einträge geben ihren Platz erst danach an den Server zurück. Währenddessen können Zugriffe kurz verzögert ankommen.
        </span>
      </p>
    </section>
  );
}
