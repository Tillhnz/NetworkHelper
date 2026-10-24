import { useId } from "react";

/** Schieberegler mit mitlaufender Füllung. Ist `optional` gesetzt, bedeutet "" automatisch und `autoText` wird angezeigt. */
export function Slider({ label, value, onChange, min, max, step = 1, format = (v) => String(v), optional, autoText = "automatisch", fallback, hint, marks }) {
  const id = useId();
  const isAuto = optional && (value === "" || value == null);
  const shown = isAuto ? (fallback ?? min) : Number(value);
  const pct = ((shown - min) / (max - min)) * 100;
  return (
    <div className={`slider ${isAuto ? "is-auto" : ""}`}>
      <div className="slider-head">
        <label htmlFor={id}>{label}</label>
        <span className="slider-value">
          {isAuto ? <span className="muted">{autoText}</span> : format(shown)}
          {optional && !isAuto && (
            <button type="button" className="slider-auto" onClick={() => onChange("")} title="Wieder automatisch bestimmen">
              automatisch
            </button>
          )}
        </span>
      </div>
      <input
        id={id}
        type="range"
        min={min}
        max={max}
        step={step}
        value={shown}
        style={{ "--pct": `${pct}%` }}
        onChange={(e) => onChange(Number(e.target.value))}
        aria-valuetext={isAuto ? autoText : format(shown)}
      />
      {marks && (
        <div className="slider-marks" aria-hidden="true">
          {marks.map((m) => <span key={m}>{m}</span>)}
        </div>
      )}
      {hint && <p className="hint">{hint}</p>}
    </div>
  );
}

/** Regler mit wenigen festen Stufen, deren Namen unter dem Regler stehen. */
export function StopSlider({ label, value, onChange, options }) {
  const id = useId();
  const idx = Math.max(0, options.findIndex((o) => o.value === value));
  const pct = options.length > 1 ? (idx / (options.length - 1)) * 100 : 0;
  return (
    <div className="slider stops">
      <div className="slider-head">
        <label htmlFor={id}>{label}</label>
        <span className="slider-value">{options[idx].label}</span>
      </div>
      <input
        id={id}
        type="range"
        min={0}
        max={options.length - 1}
        step={1}
        value={idx}
        style={{ "--pct": `${pct}%` }}
        onChange={(e) => onChange(options[Number(e.target.value)].value)}
        aria-valuetext={options[idx].label}
      />
      <div className="stop-labels">
        {options.map((o, i) => (
          <button key={o.value} type="button" tabIndex={-1} className={i === idx ? "on" : ""} onClick={() => onChange(o.value)}>
            {o.short ?? o.label}
          </button>
        ))}
      </div>
      {options[idx].hint && <p className="hint">{options[idx].hint}</p>}
    </div>
  );
}

/** Auswahl aus wenigen Optionen als Knopfreihe. */
export function Segmented({ label, value, onChange, options }) {
  return (
    <div className="segmented-wrap">
      {label && <div className="field-label">{label}</div>}
      <div className="segmented" role="radiogroup" aria-label={label}>
        {options.map((o) => (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={o.value === value}
            className={o.value === value ? "on" : ""}
            onClick={() => onChange(o.value)}
          >
            {o.label}
          </button>
        ))}
      </div>
    </div>
  );
}

export function Switch({ checked, onChange, children }) {
  return (
    <label className="switch">
      <input type="checkbox" role="switch" checked={!!checked} onChange={(e) => onChange(e.target.checked)} />
      <span className="switch-track" aria-hidden="true"><span className="switch-knob" /></span>
      <span>{children}</span>
    </label>
  );
}

/** Kleine Strichsymbole für die Kleidungsgruppen. */
const ICONS = {
  "Oberkörper": "M8 4 L3.5 7.5 L6 10.5 L8 9 V20 H16 V9 L18 10.5 L20.5 7.5 L16 4 Q12 7.5 8 4 Z",
  "Beine": "M8 3 H16 L17.5 21 H13.2 L12 10.5 L10.8 21 H6.5 Z",
  "Hände": "M8 21 V13 L5.5 10 Q5 9 6 8.5 Q7 8 8 9.5 L9 11 V5 Q9 3.8 10.2 3.8 Q11.4 3.8 11.4 5 V9 V4 Q11.4 2.8 12.6 2.8 Q13.8 2.8 13.8 4 V9 V5 Q13.8 3.8 15 3.8 Q16.2 3.8 16.2 5 V12 L17.5 10.5 Q18.5 9.5 19.3 10.3 L17 17 V21 Z",
  "Füße": "M9 3 H14 V12 L19.5 15.5 V20 H5.5 V16 L9 12.5 Z M5.5 17.5 H19.5",
  "Kopf & Hals": "M4 14.5 A8 8 0 0 1 20 14.5 Z M4 18 H20 M9 8 L10 14 M15 8 L14 14",
  "Regen & Wind": "M7 13 A3.8 3.8 0 0 1 8 5.5 A5 5 0 0 1 17 7.5 A3.2 3.2 0 0 1 17 13 Z M8.5 16 L7.5 19.5 M12.5 16 L11.5 19.5 M16.5 16 L15.5 19.5",
  "Sonne": "M12 8 A4 4 0 1 0 12.01 8 Z M12 2.5 V4.5 M12 19.5 V21.5 M2.5 12 H4.5 M19.5 12 H21.5 M5.3 5.3 L6.7 6.7 M17.3 17.3 L18.7 18.7 M18.7 5.3 L17.3 6.7 M6.7 17.3 L5.3 18.7",
  "Mitnehmen": "M7 8.5 H17 V20.5 H7 Z M9.5 8.5 V6.5 Q12 3.5 14.5 6.5 V8.5 M7 14 H17",
  "Sichtbarkeit": "M7.5 14.5 A4.5 4.5 0 1 1 16.5 14.5 Z M9.5 18 H14.5 M12 2.5 V4.5 M4.5 6.5 L6 8 M19.5 6.5 L18 8",
};

export function GroupIcon({ name }) {
  return (
    <svg viewBox="0 0 24 24" className="group-icon" aria-hidden="true" focusable="false">
      <path d={ICONS[name] ?? "M12 6 A6 6 0 1 0 12.01 6 Z"} />
    </svg>
  );
}
