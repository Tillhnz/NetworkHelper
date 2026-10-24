// Die Anmeldung steckt in einem HttpOnly-Cookie, das Skripte nicht lesen können. Früher lag sie im Browser-Speicher;
// eine solche alte Anmeldung wird einmal ins Cookie übernommen und dann gelöscht.
const LEGACY_KEY = "networkhelper_token";

let onUnauthorized = () => {};
export const setUnauthorizedHandler = (fn) => (onUnauthorized = fn);

export async function migrateLegacySession() {
  let token = null;
  try { token = localStorage.getItem(LEGACY_KEY); } catch { /* privater Modus */ }
  if (!token) return;
  try { localStorage.removeItem(LEGACY_KEY); } catch { /* egal */ }
  try {
    await fetch("/api/auth/session", { method: "POST", headers: { Authorization: `Bearer ${token}`, "X-NH-Request": "1" }, credentials: "same-origin" });
  } catch { /* dann eben neu anmelden */ }
}

export async function logoutRequest() {
  try { await fetch("/api/auth/logout", { method: "POST", headers: { "X-NH-Request": "1" }, credentials: "same-origin" }); } catch { /* egal */ }
}

async function request(method, path, body) {
  const headers = { "X-NH-Request": "1" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`/api${path}`, { method, headers, credentials: "same-origin", body: body !== undefined ? JSON.stringify(body) : undefined });
  if (res.status === 401 && !path.startsWith("/auth/login")) {
    onUnauthorized();
  }
  if (!res.ok) {
    let msg = `Fehler ${res.status}`;
    try {
      const data = await res.json();
      if (typeof data.detail === "string") msg = data.detail;
      else if (Array.isArray(data.detail)) msg = data.detail.map((d) => d.msg.replace(/^Value error, /, "")).join(", ");
    } catch {
      /* keine JSON-Antwort */
    }
    throw new Error(msg);
  }
  return res.status === 204 ? null : res.json();
}

export const api = {
  get: (p) => request("GET", p),
  post: (p, b) => request("POST", p, b ?? {}),
  put: (p, b) => request("PUT", p, b ?? {}),
  del: (p) => request("DELETE", p),
};

export const qs = (obj) => {
  const p = new URLSearchParams();
  Object.entries(obj).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== "") p.set(k, v); });
  const s = p.toString();
  return s ? `?${s}` : "";
};

// ---- Anzeige-Helfer ----

// Der Server liefert Zeiten in UTC ohne Zeitzonenangabe
export const toDate = (iso) => (iso ? new Date(/[zZ]|[+-]\d{2}:?\d{2}$/.test(iso) ? iso : iso + "Z") : null);

export const fmtDateTime = (iso) => {
  const d = toDate(iso);
  return d ? d.toLocaleString("de-DE", { dateStyle: "medium", timeStyle: "short" }) : "–";
};

export const fmtTime = (iso, withSeconds = false) => {
  const d = toDate(iso);
  return d ? d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit", ...(withSeconds ? { second: "2-digit" } : {}) }) : "–";
};

export const fmtDate = (iso) => {
  const d = toDate(iso);
  return d ? d.toLocaleDateString("de-DE") : "–";
};

export const fmtAgo = (iso) => {
  const d = toDate(iso);
  if (!d) return "nie";
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 45) return "gerade eben";
  if (s < 3600) return `vor ${Math.round(s / 60)} Min.`;
  if (s < 86400) return `vor ${Math.round(s / 3600)} Std.`;
  const days = Math.round(s / 86400);
  return `vor ${days} ${days === 1 ? "Tag" : "Tagen"}`;
};

export const fmtNum = (v, digits = 0) =>
  v == null ? "–" : new Intl.NumberFormat("de-DE", { maximumFractionDigits: digits }).format(v);

export const fmtCompact = (v) =>
  v == null ? "–" : new Intl.NumberFormat("de-DE", { notation: "compact", maximumFractionDigits: 1 }).format(v);

export const fmtBytes = (b) => {
  if (b == null) return "–";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = b;
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
  return `${fmtNum(v, v < 10 && i ? 1 : 0)} ${units[i]}`;
};

export const fmtDuration = (s) => {
  if (s == null) return "–";
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} Min.`;
  if (s < 86400) return `${Math.floor(s / 3600)} Std. ${Math.round((s % 3600) / 60)} Min.`;
  return `${Math.floor(s / 86400)} Tage ${Math.floor((s % 86400) / 3600)} Std.`;
};

const regionNames = (() => { try { return new Intl.DisplayNames(["de"], { type: "region" }); } catch { return null; } })();

export const countryName = (code) => {
  if (!code) return "Heimnetz";
  try { return regionNames?.of(code) || code; } catch { return code; }
};

export const flag = (code) =>
  code && /^[A-Z]{2}$/.test(code) ? String.fromCodePoint(...[...code].map((c) => 0x1f1a5 + c.charCodeAt(0))) : "🏠";

export const STATUS_CLASS = { 2: "Erfolg (2xx)", 3: "Weiterleitung (3xx)", 4: "Client-Fehler (4xx)", 5: "Server-Fehler (5xx)" };

export const SEVERITY = { info: "Hinweis", warn: "Warnung", crit: "Kritisch" };

export const KIND_TEXT = {
  scanner: "Suche nach Schwachstellen",
  badagent: "Angriffswerkzeug",
  bruteforce: "Anmeldeversuche",
  notfound: "Verzeichnis-Scan",
  flood: "Sehr viele Anfragen",
};

export const statusTone = (s) => (s >= 500 ? "crit" : s >= 400 ? "warn" : s >= 300 ? "info" : "ok");
