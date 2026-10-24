import { useEffect, useMemo, useRef, useState } from "react";
import { countryName, fmtNum } from "../api.js";

/** Weltkarte ohne externe Bibliothek: Länder aus /world.json (Natural Earth, Miller-Projektion), Punkte je Ort. */

export const GROUP_COLORS = { friendly: "var(--grp-friendly)", service: "var(--grp-service)", noise: "var(--grp-noise)", attack: "var(--grp-attack)" };
export const GROUP_ORDER = ["attack", "friendly", "service", "noise"];

let worldPromise = null;
const loadWorld = () => (worldPromise ||= fetch("/world.json").then((r) => { if (!r.ok) throw new Error("Karte nicht gefunden"); return r.json(); }));

const miller = (lat) => 1.25 * Math.log(Math.tan(Math.PI / 4 + 0.4 * (lat * Math.PI) / 180));

function projector(meta) {
  const top = miller(meta.latMax), bot = miller(meta.latMin);
  return (lat, lon) => [((lon + 180) / 360) * meta.w, ((top - miller(Math.max(meta.latMin, Math.min(meta.latMax, lat)))) / (top - bot)) * meta.h];
}

const PRESETS = {
  world: null,
  europe: { lat: [72, 34], lon: [-13, 42] },
  germany: { lat: [55.3, 47], lon: [5, 16] },
};

function presetBox(meta, proj, key) {
  const p = PRESETS[key];
  if (!p) return { x: 0, y: 0, w: meta.w, h: meta.h };
  const [x0, y0] = proj(p.lat[0], p.lon[0]);
  const [x1, y1] = proj(p.lat[1], p.lon[1]);
  return fitAspect({ x: x0, y: y0, w: x1 - x0, h: y1 - y0 }, meta.w / meta.h);
}

function fitAspect(b, aspect) {
  if (b.w / b.h > aspect) { const h = b.w / aspect; return { ...b, y: b.y - (h - b.h) / 2, h }; }
  const w = b.h * aspect;
  return { ...b, x: b.x - (w - b.w) / 2, w };
}

function clampBox(b, meta) {
  const w = Math.min(meta.w, Math.max(meta.w / 40, b.w));
  const h = (w * meta.h) / meta.w;
  return { w, h, x: Math.min(meta.w - w, Math.max(0, b.x)), y: Math.min(meta.h - h, Math.max(0, b.y)) };
}

export default function WorldMap({ points, countries, home, hidden = [], selected, onSelect }) {
  const [world, setWorld] = useState(null);
  const [error, setError] = useState("");
  const [box, setBox] = useState(null);
  const narrow = typeof window !== "undefined" && window.innerWidth < 640;
  const [preset, setPreset] = useState(narrow ? "europe" : "world");
  const [hover, setHover] = useState(null);
  const svgRef = useRef(null);
  const drag = useRef(null);
  const wheelRef = useRef(null);

  useEffect(() => { loadWorld().then(setWorld).catch((e) => setError(e.message)); }, []);
  const proj = useMemo(() => (world ? projector(world.meta) : null), [world]);
  useEffect(() => { if (world && !box) setBox(presetBox(world.meta, proj, preset || "world")); }, [world, proj, box]);

  useEffect(() => {
    const el = svgRef.current;
    if (!el) return undefined;
    const fn = (e) => wheelRef.current?.(e);
    el.addEventListener("wheel", fn, { passive: false });
    return () => el.removeEventListener("wheel", fn);
  }, [world, box === null]);

  const byCountry = useMemo(() => Object.fromEntries((countries || []).map((c) => [c.country, c])), [countries]);
  const maxCountry = Math.max(1, ...(countries || []).map((c) => c.count));
  const visible = useMemo(() => (points || []).filter((p) => {
    const n = Object.entries(p.groups).filter(([g]) => !hidden.includes(g)).reduce((s, [, v]) => s + v, 0);
    return n > 0;
  }).map((p) => {
    const groups = Object.fromEntries(Object.entries(p.groups).filter(([g]) => !hidden.includes(g)));
    const count = Object.values(groups).reduce((s, v) => s + v, 0);
    return { ...p, vcount: count, vgroup: Object.keys(groups).sort((a, b) => groups[b] - groups[a])[0] };
  }), [points, hidden]);
  const maxPoint = Math.max(1, ...visible.map((p) => p.vcount));

  if (error) return <p className="error">{error}</p>;
  if (!world || !box) return <div className="map-wrap map-loading" aria-busy="true" />;

  const meta = world.meta;
  const k = box.w / meta.w; // 1 = ganze Welt; Punktgrößen bleiben auf dem Bildschirm gleich
  const homeXY = home ? proj(home.lat, home.lon) : null;

  function toSvg(e) {
    const r = svgRef.current.getBoundingClientRect();
    return [box.x + ((e.clientX - r.left) / r.width) * box.w, box.y + ((e.clientY - r.top) / r.height) * box.h];
  }
  function zoom(factor, center) {
    const [cx, cy] = center || [box.x + box.w / 2, box.y + box.h / 2];
    const w = box.w * factor, h = box.h * factor;
    setBox(clampBox({ x: cx - ((cx - box.x) / box.w) * w, y: cy - ((cy - box.y) / box.h) * h, w, h }, meta));
    setPreset("");
  }
  wheelRef.current = (e) => {
    if (!e.ctrlKey && !e.metaKey) return; // normales Scrollen bewegt die Seite
    e.preventDefault();
    zoom(e.deltaY > 0 ? 1.2 : 0.83, toSvg(e));
  };
  function onPointerDown(e) {
    if (e.target.closest(".map-dot")) return;
    drag.current = { x: e.clientX, y: e.clientY, box, moved: false };
    svgRef.current.setPointerCapture(e.pointerId);
  }
  function onPointerMove(e) {
    const d = drag.current;
    if (!d) return;
    const r = svgRef.current.getBoundingClientRect();
    const dx = ((e.clientX - d.x) / r.width) * d.box.w, dy = ((e.clientY - d.y) / r.height) * d.box.h;
    if (Math.abs(e.clientX - d.x) + Math.abs(e.clientY - d.y) > 3) d.moved = true;
    setBox(clampBox({ ...d.box, x: d.box.x - dx, y: d.box.y - dy }, meta));
    setPreset("");
  }
  function onPointerUp(e) {
    if (e.type === "pointercancel") { drag.current = null; return; }
    if (drag.current && !drag.current.moved) onSelect?.(null);
    drag.current = null;
  }
  const go = (key) => { setPreset(key); setBox(presetBox(meta, proj, key)); };

  const arcs = homeXY ? visible.slice(0, 80) : [];
  const radius = (p) => (2.5 + 9 * Math.sqrt(Math.log(1 + p.vcount) / Math.log(1 + maxPoint))) * k;

  return (
    <div className="map-wrap">
      <div className="map-tools">
        <div className="segmented small" role="radiogroup" aria-label="Ausschnitt">
          {[["world", "Welt"], ["europe", "Europa"], ["germany", "Deutschland"]].map(([key, label]) => (
            <button key={key} type="button" role="radio" aria-checked={preset === key} className={preset === key ? "on" : ""} onClick={() => go(key)}>{label}</button>
          ))}
        </div>
        <div className="map-zoom">
          <button type="button" className="btn icon" onClick={() => zoom(0.66)} aria-label="Hineinzoomen">+</button>
          <button type="button" className="btn icon" onClick={() => zoom(1.5)} aria-label="Herauszoomen">−</button>
        </div>
      </div>
      <svg
        ref={svgRef}
        className="map"
        viewBox={`${box.x} ${box.y} ${box.w} ${box.h}`}
        role="img"
        aria-label={`Weltkarte mit ${visible.length} Herkunftsorten`}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
        onPointerLeave={() => { drag.current = null; setHover(null); }}
      >
        <rect x="0" y="0" width={meta.w} height={meta.h} className="map-sea" />
        <g className="map-land" strokeWidth={0.35 * k}>
          {world.countries.map((c) => {
            const hit = byCountry[c.c];
            const t = hit ? Math.log(1 + hit.count) / Math.log(1 + maxCountry) : 0;
            return (
              <path key={c.c + c.d.length} d={c.d} className={hit ? "has" : ""} style={hit ? { fillOpacity: 0.06 + 0.22 * t } : undefined}>
                <title>{`${c.n}${hit ? `: ${fmtNum(hit.count)} Zugriffe von ${fmtNum(hit.ips)} Adressen` : ""}`}</title>
              </path>
            );
          })}
        </g>
        <g className="map-arcs" strokeWidth={0.6 * k}>
          {arcs.map((p) => {
            const [x, y] = proj(p.lat, p.lon);
            const [hx, hy] = homeXY;
            const dist = Math.hypot(hx - x, hy - y);
            if (dist < 2 * k) return null;
            const mx = (x + hx) / 2, my = (y + hy) / 2 - dist * 0.25;
            return <path key={`a${p.lat},${p.lon}`} d={`M${x},${y} Q${mx},${my} ${hx},${hy}`} stroke={GROUP_COLORS[p.vgroup]} strokeOpacity={0.25 + 0.4 * Math.log(1 + p.vcount) / Math.log(1 + maxPoint)} />;
          })}
        </g>
        <g>
          {[...visible].reverse().map((p) => {
            const [x, y] = proj(p.lat, p.lon);
            const isSel = selected && selected.lat === p.lat && selected.lon === p.lon;
            return (
              <circle
                key={`${p.lat},${p.lon}`}
                className={`map-dot ${isSel ? "sel" : ""}`}
                cx={x}
                cy={y}
                r={radius(p)}
                fill={GROUP_COLORS[p.vgroup]}
                strokeWidth={(isSel ? 1.6 : 0.6) * k}
                tabIndex={0}
                role="button"
                aria-label={`${p.city || countryName(p.country)}: ${fmtNum(p.vcount)} Zugriffe`}
                onPointerEnter={(e) => e.pointerType === "mouse" && setHover({ p, e })}
                onPointerMove={(e) => e.pointerType === "mouse" && setHover({ p, e })}
                onPointerLeave={() => setHover(null)}
                onClick={() => onSelect?.(p)}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect?.(p); } }}
              />
            );
          })}
        </g>
        {homeXY && (
          <g className="map-home" transform={`translate(${homeXY[0]},${homeXY[1]}) scale(${k})`}>
            <circle r="6" className="ring" />
            <circle r="2.6" />
            <title>Dein Server{home.city ? ` (${home.city})` : ""}</title>
          </g>
        )}
      </svg>
      {hover && <MapTip hover={hover} wrap={svgRef.current} />}
      <p className="map-credit">Kartendaten: Natural Earth · Standorte: DB-IP (CC BY 4.0) <span className="hide-sm"> · Ziehen zum Verschieben, Strg + Mausrad zum Zoomen</span></p>
    </div>
  );
}

function MapTip({ hover, wrap }) {
  const { p, e } = hover;
  const r = wrap.getBoundingClientRect();
  const left = Math.min(r.width - 220, Math.max(0, e.clientX - r.left + 14));
  const top = Math.max(0, e.clientY - r.top + 14);
  const groups = GROUP_ORDER.filter((g) => p.groups[g]);
  return (
    <div className="map-tip" style={{ left, top }}>
      <strong>{p.city ? `${p.city}, ` : ""}{countryName(p.country)}</strong>
      {!p.exact && <span className="muted small"> (Land, ohne Stadt)</span>}
      <div className="small">{fmtNum(p.count)} Zugriffe von {fmtNum(p.ips)} {p.ips === 1 ? "Adresse" : "Adressen"}</div>
      <ul className="map-tip-groups">
        {groups.map((g) => <li key={g}><span className="swatch" style={{ background: GROUP_COLORS[g] }} />{fmtNum(p.groups[g])}</li>)}
      </ul>
      {p.top[0] && <div className="small muted">Meist: {p.top[0].who || p.top[0].label}</div>}
    </div>
  );
}
