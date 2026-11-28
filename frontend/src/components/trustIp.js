import { api } from "../api.js";
import { toast, confirmDialog } from "./feedback.jsx";

/** „Das war ich“: überall entsperren und 24 Stunden lang nicht wieder sperren. Gibt true zurück, wenn ausgeführt. */
export async function trustIp(ip) {
  if (!(await confirmDialog(
    `${ip} überall entsperren und 24 Stunden lang nicht wieder sperren? Nimm das nur, wenn das wirklich dein Gerät war, zum Beispiel dein Handy im Mobilfunk.`,
    { title: "Das war ich", confirmLabel: "Ja, das war ich", danger: false },
  ))) return false;
  try {
    await api.post("/security/trust", { ip });
    toast(`${ip} entsperrt und für 24 Stunden ausgenommen. Die Server übernehmen das innerhalb einer Minute.`);
    return true;
  } catch (e) { toast(e.message, "error"); return false; }
}
