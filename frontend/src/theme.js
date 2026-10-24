// Darstellung: "auto" folgt dem Gerät, "light" und "dark" erzwingen eine Seite. Gespeichert wird nur im Browser.
const KEY = "networkhelper-theme";

export function getTheme() {
  try { return localStorage.getItem(KEY) || "auto"; } catch { return "auto"; }
}

export function setTheme(mode) {
  try { if (mode === "auto") localStorage.removeItem(KEY); else localStorage.setItem(KEY, mode); } catch { /* privater Modus */ }
  applyTheme();
}

/** Das aktuell sichtbare Schema ("light" oder "dark"), auch im Modus "auto". */
export function effectiveTheme() {
  const mode = getTheme();
  if (mode !== "auto") return mode;
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

export function applyTheme() {
  const mode = getTheme();
  const root = document.documentElement;
  if (mode === "auto") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", mode);
  const light = mode === "light" || (mode === "auto" && window.matchMedia?.("(prefers-color-scheme: light)").matches);
  window.dispatchEvent(new Event("themechange"));
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", light ? "#f3f6f8" : "#0e1620");
}
