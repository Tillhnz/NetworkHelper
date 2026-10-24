"""Domain gegen Missbrauch absichern: Wer darf in deinem Namen E-Mails verschicken, wer darf Zertifikate ausstellen?

Für Domains ohne E-Mail ist die Empfehlung eindeutig und kann per Klick bei Porkbun gesetzt werden:
  - Null-MX (MX 0 .): „Diese Domain empfängt keine Mails“
  - SPF „v=spf1 -all“: „Von hier kommt keine Mail“
  - DMARC „p=reject“: „Gefälschte Mails ablehnen“
Für alle Domains:
  - CAA „0 issue letsencrypt.org“: nur Let's Encrypt darf Zertifikate ausstellen (das nutzt der Proxy Manager).
Domains mit E-Mail bekommen nur Hinweise, weil die richtigen Werte vom Mail-Anbieter abhängen.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from . import porkbun, state

FIXES = {
    "null_mx": {"name": "", "type": "MX", "content": ".", "prio": "0"},
    "spf": {"name": "", "type": "TXT", "content": "v=spf1 -all"},
    "dmarc": {"name": "_dmarc", "type": "TXT", "content": "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"},
    "dmarc_monitor": {"name": "_dmarc", "type": "TXT", "content": "v=DMARC1; p=none"},
    "caa": {"name": "", "type": "CAA", "content": '0 issue "letsencrypt.org"'},
}


def _txt(r: dict) -> str:
    return str(r.get("content") or "").strip().strip('"').strip()


def analyze(domain: str, recs: list[dict]) -> dict:
    root = [r for r in recs if (r.get("name") or "") == ""]
    mx = [r for r in root if r.get("type") == "MX"]
    real_mx = [r for r in mx if _txt(r) not in (".", "")]
    null_mx = [r for r in mx if _txt(r) == "."]
    spf = [_txt(r) for r in root if r.get("type") == "TXT" and _txt(r).lower().startswith("v=spf1")]
    dmarc = [_txt(r) for r in recs if r.get("name") == "_dmarc" and r.get("type") == "TXT" and _txt(r).upper().startswith("V=DMARC1")]
    caa = [_txt(r) for r in root if r.get("type") == "CAA"]
    mail = bool(real_mx)
    checks = []

    def add(key, label, ok, detail, fix=None, severity="warn"):
        checks.append({"key": key, "label": label, "ok": ok, "detail": detail, "fix": fix if not ok else None, "severity": severity})

    if not mail:
        add("null_mx", "Empfängt keine Mails (Null-MX)", bool(null_mx),
            "gesetzt" if null_mx else "Fehlt: Mailserver probieren sonst, an deine Domain zuzustellen.", "null_mx", "info")
        if not spf:
            add("spf", "Verbietet Mails in deinem Namen (SPF)", False, "Fehlt: Jeder kann Mails mit Absender @" + domain + " verschicken.", "spf")
        else:
            strict = any(s.endswith("-all") and len(s.split()) == 2 for s in spf)
            add("spf", "Verbietet Mails in deinem Namen (SPF)", strict, spf[0] if strict else
                f"Vorhanden, aber nicht streng: „{spf[0]}“. Für eine Domain ohne Mail sollte er genau „v=spf1 -all“ lauten. Bei Porkbun ändern.")
        if not dmarc:
            add("dmarc", "Lässt gefälschte Mails ablehnen (DMARC)", False, "Fehlt: Empfänger wissen nicht, dass sie Fälschungen ablehnen sollen.", "dmarc")
        else:
            strict = "p=reject" in dmarc[0].replace(" ", "").lower()
            add("dmarc", "Lässt gefälschte Mails ablehnen (DMARC)", strict, dmarc[0] if strict else
                f"Vorhanden, aber nicht auf Ablehnen: „{dmarc[0]}“. Für eine Domain ohne Mail ist p=reject richtig.")
    else:
        add("spf", "SPF für deinen Mail-Anbieter", bool(spf), spf[0] if spf else
            "Fehlt. Den passenden Eintrag nennt dein Mail-Anbieter (z. B. „v=spf1 include:… -all“).")
        add("dmarc", "DMARC", bool(dmarc), dmarc[0] if dmarc else
            "Fehlt. Ein vorsichtiger Anfang ist „v=DMARC1; p=none“ (nur beobachten), später p=quarantine.", "dmarc_monitor")
    if not caa:
        add("caa", "Nur Let's Encrypt darf Zertifikate ausstellen (CAA)", False,
            "Fehlt: Jede Zertifizierungsstelle dürfte Zertifikate für deine Domain ausstellen.", "caa", "info")
    else:
        le = any("letsencrypt.org" in c for c in caa)
        add("caa", "Nur Let's Encrypt darf Zertifikate ausstellen (CAA)", le, ", ".join(caa) if le else
            f"Vorhanden, aber ohne Let's Encrypt ({', '.join(caa)}): Der Proxy Manager kann dann keine Zertifikate mehr erneuern!", None, "crit")
    open_ = [c for c in checks if not c["ok"]]
    return {"domain": domain, "mail": mail, "checks": checks, "ok": not open_,
            "open": len([c for c in open_ if c["severity"] != "info"])}


def run(db: Session) -> dict:
    out = []
    for d in porkbun.managed_domains():
        try:
            out.append(analyze(d, porkbun.records(d)))
        except porkbun.PorkbunError as e:
            out.append({"domain": d, "error": str(e), "checks": [], "ok": False, "open": 0})
    result = {"checked": datetime.utcnow().isoformat(), "domains": out}
    state.put(db, "domainguard", result)
    return result


def apply_fix(domain: str, key: str) -> str:
    fix = FIXES.get(key)
    if fix is None:
        raise ValueError("Unbekannte Empfehlung")
    return porkbun.create(domain, fix["name"], fix["type"], fix["content"], ttl=3600, notes="NetworkHelper Domain-Schutz",
                          prio=fix.get("prio"))
