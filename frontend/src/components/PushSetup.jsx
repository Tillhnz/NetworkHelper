import { useEffect, useState } from "react";
import { api } from "../api.js";
import { toast } from "./feedback.jsx";

function randomTopic() {
  const a = new Uint8Array(6);
  crypto.getRandomValues(a);
  return "nh-" + Array.from(a, (b) => "abcdefghjkmnpqrstuvwxyz23456789"[b % 31]).join("");
}

/** Push über ntfy einrichten (nur Administratoren). */
export default function PushSetup() {
  const [cfg, setCfg] = useState(null);
  const [topic, setTopic] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    api.get("/admin/settings").then((d) => {
      const f = d.fields || {};
      setCfg(f);
      setTopic(f.ntfy_topic?.value || "");
    }).catch(() => setCfg({}));
  }, []);
  if (!cfg) return null;
  if (!cfg.ntfy_topic) return <p className="muted small">Bitte NetworkHelper aktualisieren (Administration → Übersicht → Update), dann erscheint hier die Einrichtung.</p>;
  const saved = cfg.ntfy_topic.value;

  async function save() {
    setBusy(true);
    try {
      await api.put("/admin/settings", { values: { ntfy_topic: topic.trim() } });
      setCfg({ ...cfg, ntfy_topic: { ...cfg.ntfy_topic, value: topic.trim() } });
      if (topic.trim()) {
        await api.post("/admin/settings/test-push", {});
        toast("Gespeichert und Test-Push gesendet.");
      } else toast("Push ausgeschaltet.");
    } catch (e) { toast(e.message, "error"); } finally { setBusy(false); }
  }
  return (
    <div className="push-setup">
      <ol className="small steps-list">
        <li>App <strong>ntfy</strong> aufs Handy laden (iPhone und Android, kostenlos).</li>
        <li>Hier ein Thema festlegen und speichern. Der Vorschlag ist zufällig, damit niemand deine Meldungen errät.</li>
        <li>In der App auf „+“ tippen und genau dieses Thema abonnieren (Server: {cfg.ntfy_url?.value || "ntfy.sh"}).</li>
      </ol>
      <div className="inline-form">
        <label className="grow">Thema
          <input value={topic} onChange={(e) => setTopic(e.target.value)} placeholder="nh-…" pattern="[A-Za-z0-9_-]{0,64}" />
        </label>
        {!topic && <button type="button" className="btn" onClick={() => setTopic(randomTopic())}>Vorschlag</button>}
        <button type="button" className="btn primary" onClick={save} disabled={busy || topic.trim() === saved}>{busy ? "…" : "Speichern & testen"}</button>
        {saved && topic.trim() === saved && <button type="button" className="btn" onClick={() => api.post("/admin/settings/test-push", {}).then(() => toast("Test-Push gesendet.")).catch((e) => toast(e.message, "error"))}>Test-Push</button>}
      </div>
      <p className="muted small">{saved ? <>Aktiv: Warnungen ab Stufe „{{ info: "Hinweis", warn: "Warnung", crit: "kritisch" }[cfg.ntfy_min_level?.value] || "Warnung"}“ kommen aufs Handy. Feinheiten (eigener Server, Token) unter Administration → E-Mail & Push.</> : "Noch nicht eingerichtet."}</p>
    </div>
  );
}
