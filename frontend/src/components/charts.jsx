import { useState } from "react";
import { fmtNum, toDate } from "../api.js";

export const CLASS_COLORS = { 2: "var(--celeste)", 3: "var(--sky)", 4: "var(--amber)", 5: "var(--signal)" };
const CLASS_LABEL = { 2: "2xx", 3: "3xx", 4: "4xx", 5: "5xx" };

function label(iso, bucket) {
  const d = toDate(iso);
  if (bucket >= 86400) return d.toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit" });
  if (bucket >= 3 * 3600) return d.toLocaleDateString("de-DE", { weekday: "short" }) + " " + d.getHours() + "h";
  return d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });
}

function tipLabel(iso, bucket) {
  const d = toDate(iso);
  if (bucket >= 86400) return d.toLocaleDateString("de-DE", { weekday: "short", day: "2-digit", month: "2-digit" });
  return d.toLocaleString("de-DE", { weekday: "short", hour: "2-digit", minute: "2-digit" });
}

/** Gestapelte Säulen je Zeitabschnitt, getrennt nach Statusklasse. series: [{t, "2", "3", "4", "5"}] */
export function TrafficBars({ series, bucket = 3600, height = 190, onPick }) {
  const [hover, setHover] = useState(null);
  const W = 720, padB = 24, padT = 22, padL = 36;
  const totals = series.map((s) => s["2"] + s["3"] + s["4"] + s["5"]);
  const max = Math.max(1, ...totals);
  const bw = (W - padL) / Math.max(1, series.length);
  const h = height - padB - padT;
  const every = Math.max(1, Math.ceil(series.length / 8));
  const hs = hover != null ? series[hover] : null;
  return (
    <svg viewBox={`0 0 ${W} ${height}`} className="chart" role="img" aria-label="Zugriffe im Zeitverlauf">
      {[0, 0.5, 1].map((f) => (
        <g key={f}>
          <line x1={padL} x2={W} y1={padT + h * (1 - f)} y2={padT + h * (1 - f)} className="chart-grid" />
          <text x={padL - 6} y={padT + h * (1 - f) + 4} textAnchor="end" className="chart-label">{fmtNum(max * f)}</text>
        </g>
      ))}
      {series.map((s, i) => {
        let y = padT + h;
        const x = padL + i * bw;
        return (
          <g key={s.t} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)} onClick={() => onPick?.(s)} style={{ cursor: onPick ? "pointer" : undefined }}>
            <rect x={x} y={padT} width={bw} height={h} fill="transparent" />
            {["2", "3", "4", "5"].map((k) => {
              const bh = (s[k] / max) * h;
              y -= bh;
              return bh > 0 ? (
                <rect key={k} className="bar-grow" style={{ "--i": i }} x={x + bw * 0.12} y={y} width={Math.max(1, bw * 0.76)} height={bh}
                      fill={CLASS_COLORS[k]} opacity={hover === null || hover === i ? 1 : 0.4} rx={bw > 8 ? 2 : 0} />
              ) : null;
            })}
            {i % every === 0 && <text x={x + bw / 2} y={height - 7} textAnchor="middle" className="chart-label">{label(s.t, bucket)}</text>}
          </g>
        );
      })}
      {hs && (
        <text x={Math.min(Math.max(padL + hover * bw + bw / 2, 140), W - 140)} y="12" textAnchor="middle" className="chart-tip">
          {tipLabel(hs.t, bucket)}: {fmtNum(totals[hover])} Zugriffe
          {["4", "5"].filter((k) => hs[k]).map((k) => ` · ${fmtNum(hs[k])} ${CLASS_LABEL[k]}`).join("")}
        </text>
      )}
    </svg>
  );
}

export function Legend() {
  return (
    <div className="legend">
      {Object.entries(CLASS_LABEL).map(([k, l]) => <span key={k}><i style={{ background: CLASS_COLORS[k] }} />{l}</span>)}
    </div>
  );
}

/** Waagerechte Balken für Ranglisten. items: [{key, label, value, sub?, onClick?}] */
export function HBars({ items, color = "var(--celeste)", format = (v) => fmtNum(v) }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <ul className="hbars">
      {items.map((it, i) => (
        <li key={it.key ?? it.label}>
          {it.onClick
            ? <button className="hbar-label linklike" onClick={it.onClick} title={typeof it.label === "string" ? it.label : undefined}>{it.label}</button>
            : <span className="hbar-label" title={typeof it.label === "string" ? it.label : undefined}>{it.label}</span>}
          <span className="hbar-track"><span className="hbar-fill" style={{ width: `${(it.value / max) * 100}%`, background: it.color || color, "--i": i }} /></span>
          <span className="hbar-val">{format(it.value)}{it.sub && <span className="muted small"> {it.sub}</span>}</span>
        </li>
      ))}
    </ul>
  );
}

/** Verfügbarkeit als Leiste kleiner Abschnitte, wie auf Statusseiten. history: [{t, up, checks, latency}] */
export function UptimeStrip({ history }) {
  return (
    <div className="uptime-strip" role="img" aria-label="Verfügbarkeit der letzten 24 Stunden">
      {history.map((h, i) => {
        const tone = h.up == null ? "none" : h.up >= 0.999 ? "up" : h.up >= 0.5 ? "part" : "down";
        const when = toDate(h.t).toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });
        const text = h.up == null ? "keine Prüfung" : `${fmtNum(h.up * 100, 1)} % erreichbar${h.latency ? `, ${h.latency} ms` : ""}`;
        return <span key={i} className={`us us-${tone}`} title={`${when}: ${text}`} style={{ "--i": i }} />;
      })}
    </div>
  );
}

/** Kleine Linie für Antwortzeiten. */
export function Sparkline({ values, width = 120, height = 28 }) {
  const pts = values.map((v, i) => [i, v]).filter(([, v]) => v != null);
  if (pts.length < 2) return <svg width={width} height={height} aria-hidden="true" />;
  const max = Math.max(...pts.map(([, v]) => v));
  const min = Math.min(...pts.map(([, v]) => v));
  const sx = (i) => (i / (values.length - 1)) * (width - 2) + 1;
  const sy = (v) => height - 3 - ((v - min) / Math.max(1, max - min)) * (height - 6);
  const d = pts.map(([i, v], k) => `${k ? "L" : "M"}${sx(i).toFixed(1)},${sy(v).toFixed(1)}`).join("");
  return (
    <svg width={width} height={height} className="sparkline" aria-hidden="true">
      <path d={d} pathLength="1" className="line-draw" />
    </svg>
  );
}
