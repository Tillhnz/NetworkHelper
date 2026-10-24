import { useCallback, useMemo, useState } from "react";
import { api, fmtAgo, fmtBytes, fmtDuration, fmtNum } from "../api.js";
import { Segmented, Switch } from "../components/controls.jsx";
import { confirmDialog, Loading, toast } from "../components/feedback.jsx";
import { CopyLine, Country, Dot, EmptyState, Pill, usePoll } from "../components/ui.jsx";
import { IpDetail } from "./Access.jsx";
import { InfoTip, PageIntro, Term } from "../components/help.jsx";

function installCommand(server, token, enforce) {
  return `curl -fsSL ${server}/api/agent/files/install.sh | bash -s -- --server ${server} --token ${token}${enforce ? " --enforce-blocks" : ""}`;
}

/** Zeigt den Installationsbefehl nach dem Anlegen oder Erneuern; der Token ist nur jetzt sichtbar. */
function InstallBox({ created, onDone }) {
  const [server, setServer] = useState(window.location.origin);
  const [enforce, setEnforce] = useState(false);
  return (
    <section className="panel install-box">
      <h2>Agent „{created.name}“ installieren</h2>
      <ol className="steps">
        <li>Öffne eine Konsole auf dem Server oder LXC mit dem Nginx Proxy Manager (in Proxmox: Container → Console, oder per SSH).</li>
        <li>Prüfe die Adresse: Der Server muss NetworkHelper darunter erreichen. Im Heimnetz ist die interne Adresse meist die beste Wahl.</li>
        <li>Führe den Befehl als root aus (in der Proxmox-Konsole bist du das automatisch). Er installiert Python (falls nötig), den Agenten und einen systemd-Dienst und findet den Proxy Manager selbst.</li>
      </ol>
      <div className="form-grid">
        <label className="span-all">Adresse von NetworkHelper
          <input value={server} onChange={(e) => setServer(e.target.value.replace(/\/$/, ""))} />
        </label>
        <div className="span-all"><Switch checked={enforce} onChange={setEnforce}>Sperrliste im Proxy Manager umsetzen (deny-Regeln, nginx wird dabei neu geladen)</Switch></div>
      </div>
      <CopyLine text={installCommand(server, created.token, enforce)} />
      <p className="muted small">Der Token erscheint nur jetzt. Geht er verloren, erzeugst du beim Agenten einfach einen neuen. Ohne Proxy Manager meldet der Agent nur Verbindungen, das ist auf weiteren Servern auch nützlich.</p>
      <div className="actions"><button className="btn primary" onClick={onDone}>Fertig</button></div>
    </section>
  );
}

function AgentCard({ a, isAdmin, onChanged, onIp }) {
  const [scope, setScope] = useState("public");
  const [showAll, setShowAll] = useState(false);
  const est = useMemo(() => a.established.filter((c) => scope === "all" || c.scope === "public"), [a.established, scope]);
  const byRemote = useMemo(() => {
    const m = new Map();
    for (const c of est) {
      const k = `${c.remote}|${c.lport}`;
      const cur = m.get(k) || { ...c, count: 0 };
      cur.count += 1;
      m.set(k, cur);
    }
    return [...m.values()].sort((x, y) => y.count - x.count);
  }, [est]);
  const info = a.info || {};
  const memUsed = info.mem_total ? 1 - info.mem_available / info.mem_total : null;
  const shown = showAll ? byRemote : byRemote.slice(0, 15);

  async function renew() {
    if (!(await confirmDialog("Der bisherige Token wird ungültig. Danach musst du den Installationsbefehl auf dem Server erneut ausführen.", { title: "Neuen Token erzeugen?", confirmLabel: "Erzeugen", danger: false }))) return;
    try { onChanged(await api.post(`/agents/${a.id}/token`, {})); } catch (e) { toast(e.message, "error"); }
  }
  async function remove() {
    if (!(await confirmDialog(`Agent „${a.name}“ entfernen? Bereits gelieferte Zugriffe bleiben erhalten. Auf dem Server deinstallierst du ihn mit: install.sh --uninstall`))) return;
    try { await api.del(`/agents/${a.id}`); toast("Agent entfernt."); onChanged(null); } catch (e) { toast(e.message, "error"); }
  }

  return (
    <section className="panel agent">
      <div className="agent-head">
        <div>
          <h2><Dot tone={a.online ? "ok" : "crit"} pulse={a.online} label={a.online ? "online" : "offline"} /> {a.name}</h2>
          <p className="muted small">
            {a.hostname || "noch nicht verbunden"}{info.os ? ` · ${info.os}` : ""}{info.container ? ` · ${info.container.toUpperCase()}` : ""}
            {a.version ? ` · Agent ${a.version}` : ""} · zuletzt {fmtAgo(a.last_seen)}
          </p>
        </div>
        {isAdmin && (
          <div className="rule-actions">
            <button className="link small" onClick={renew}>Neuer Token</button>
            <button className="link small danger" onClick={remove}>Entfernen</button>
          </div>
        )}
      </div>

      {a.last_seen && (
        <dl className="facts row">
          {info.addrs?.length > 0 && <div><dt>Adressen</dt><dd className="mono small">{info.addrs.slice(0, 3).join(", ")}</dd></div>}
          {info.uptime_s != null && <div><dt>Läuft seit</dt><dd>{fmtDuration(info.uptime_s)}</dd></div>}
          {info.load && <div><dt>Last</dt><dd>{info.load.join(" · ")}</dd></div>}
          {memUsed != null && <div><dt>Arbeitsspeicher</dt><dd>{Math.round(memUsed * 100)} % von {fmtBytes(info.mem_total)}</dd></div>}
          <div><dt>Protokollzeilen</dt><dd>{fmtNum(a.lines_total)}{a.parse_errors > 0 && <span className="muted small"> ({fmtNum(a.parse_errors)} unlesbar)</span>}</dd></div>
          <div><dt><Term k="blocklist">Sperrliste</Term></dt><dd>{a.enforce_blocks ? <Pill status="ok">{a.block_status || "aktiv"}</Pill> : <span className="muted">nicht umgesetzt</span>}</dd></div>
        </dl>
      )}

      {a.log_files.length > 0 && (
        <details className="howto">
          <summary>{a.log_files.length} beobachtete Protokolldateien</summary>
          <ul className="plain-list small mono">{a.log_files.map((f) => <li key={f.path}>{f.path} <span className="muted">({fmtBytes(f.size)})</span></li>)}</ul>
        </details>
      )}
      {a.last_seen && a.log_files.length === 0 && <p className="muted small">Keine Protokolldateien gefunden: Dieser Agent liefert nur Verbindungen.</p>}

      {a.last_seen && (
        <div className="grid-2 tight">
          <div>
            <div className="panel-head sub">
              <h3 className="sub-title">Aktive Verbindungen ({fmtNum(est.length)}) <InfoTip k="connection" /></h3>
              <Segmented value={scope} onChange={setScope} options={[{ value: "public", label: "Von außen" }, { value: "all", label: "Alle" }]} />
            </div>
            {byRemote.length === 0 ? <p className="muted small">Gerade keine {scope === "public" ? "Verbindungen aus dem Internet" : "Verbindungen"}.</p> : (
              <div className="table-wrap flat">
                <table className="rows">
                  <thead><tr><th>Gegenstelle</th><th>Port</th><th>Dienst</th><th className="num">Anz.</th></tr></thead>
                  <tbody>
                    {shown.map((c) => (
                      <tr key={`${c.remote}|${c.lport}`} className={c.blocked ? "is-blocked" : ""}>
                        <td className="nowrap"><Country code={c.country} org={c.scope === "public" ? c.as_org : "Heimnetz"} compact />{" "}
                          {c.scope === "public" ? <button className="linklike mono" onClick={() => onIp(c.remote)}>{c.remote}</button> : <span className="mono">{c.remote}</span>}
                          {c.as_org && c.scope === "public" && <div className="muted small ellipsis">{c.as_org}</div>}</td>
                        <td className="mono">{c.lport}</td>
                        <td className="small">{c.process || "–"}</td>
                        <td className="num">{c.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {byRemote.length > 15 && <button className="link small" onClick={() => setShowAll(!showAll)}>{showAll ? "Weniger" : `Alle ${byRemote.length} zeigen`}</button>}
          </div>
          <div>
            <h3 className="sub-title">Offene <Term k="port">Ports</Term> auf dem Server ({a.listening.length})</h3>
            <ul className="port-chips">
              {a.listening.map((l) => (
                <li key={`${l.proto}${l.port}${l.process}`} title={`${l.addr}:${l.port}`}>
                  <strong className="mono">{l.port}</strong><span className="muted small">{l.proto}</span><span className="small">{l.process || "?"}</span>
                </li>
              ))}
            </ul>
            {info.docker?.length > 0 && (
              <>
                <h3 className="sub-title">Docker-Container</h3>
                <ul className="plain-list small">{info.docker.map((d) => <li key={d.name}><strong>{d.name}</strong> <span className="muted mono">{d.ports}</span></li>)}</ul>
              </>
            )}
          </div>
        </div>
      )}
      {!a.last_seen && <p className="muted">Noch keine Verbindung. Führe den Installationsbefehl auf dem Server aus.</p>}
    </section>
  );
}

export default function Connections({ user }) {
  const isAdmin = user.role === "admin";
  const [agents, setAgents] = useState(null);
  const [error, setError] = useState("");
  const [created, setCreated] = useState(null);
  const [name, setName] = useState("");
  const [ip, setIp] = useState(null);
  const load = useCallback(() => api.get("/connections").then((d) => { setAgents(d); setError(""); }).catch((e) => setError(e.message)), []);
  usePoll(load, 15000);

  async function create(e) {
    e.preventDefault();
    try {
      const r = await api.post("/agents", { name: name.trim() || "Proxy-Server" });
      setCreated(r);
      setName("");
      load();
    } catch (err) { toast(err.message, "error"); }
  }

  return (
    <>
      <header className="page-head"><h1>Verbindungen</h1></header>
      <PageIntro id="connections" />
      {error && <p className="error" role="alert">{error}</p>}
      {created && <InstallBox created={created} onDone={() => setCreated(null)} />}
      <div data-tour="agents">
      {isAdmin && !created && (
        <form className="inline-form" onSubmit={create}>
          <label className="grow"><span>Neuer <Term k="agent">Agent</Term></span>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="z. B. Proxy-LXC" maxLength={80} />
          </label>
          <button className="btn primary">Agent hinzufügen</button>
        </form>
      )}
      {!agents ? <Loading rows={2} /> : agents.length === 0 ? (
        <EmptyState title="Noch kein Agent" text="Lege einen Agenten an und führe den angezeigten Befehl auf dem LXC mit dem Nginx Proxy Manager aus." />
      ) : agents.map((a) => (
        <AgentCard key={a.id} a={a} isAdmin={isAdmin} onIp={setIp} onChanged={(r) => { if (r?.token) setCreated(r); load(); }} />
      ))}
      </div>
      {ip && <IpDetail ip={ip} onClose={() => setIp(null)} onFilter={(x) => { window.location.href = `/access?ip=${encodeURIComponent(x)}`; }} isAdmin={isAdmin} />}
    </>
  );
}
