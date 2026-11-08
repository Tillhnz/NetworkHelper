"""CVSS-Basiswert aus einem Vektor berechnen (Version 3.0/3.1 exakt, Version 4.0 grob genähert).

Die Lückendatenbank OSV liefert die Schwere nur als Vektor wie „CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H“.
"""
from __future__ import annotations

import math

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def _parts(vector: str) -> dict:
    out = {}
    for p in vector.split("/")[1:]:
        k, _, v = p.partition(":")
        out[k] = v
    return out


def v3(vector: str) -> float | None:
    m = _parts(vector)
    try:
        changed = m["S"] == "C"
        iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * AV[m["AV"]] * AC[m["AC"]] * (PR_C if changed else PR_U)[m["PR"]] * UI[m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + expl), 10)) if changed else _roundup(min(impact + expl, 10))


def v4(vector: str) -> float | None:
    """Näherung für CVSS 4.0 (die exakte Berechnung braucht eine große Tabelle): genügt für kritisch/hoch/mittel."""
    m = _parts(vector)
    try:
        net = {"N": 1.0, "A": 0.8, "L": 0.6, "P": 0.3}[m["AV"]]
        easy = (1.0 if m["AC"] == "L" else 0.8) * (1.0 if m.get("AT", "N") == "N" else 0.85)
        priv = {"N": 1.0, "L": 0.8, "H": 0.6}[m["PR"]]
        ui = {"N": 1.0, "P": 0.85, "A": 0.75}[m["UI"]]
        impact = max(CIA[m["VC"]], CIA[m["VI"]], CIA[m["VA"]]) / 0.56
        sub = max(CIA.get(m.get("SC", "N"), 0), CIA.get(m.get("SI", "N"), 0), CIA.get(m.get("SA", "N"), 0)) / 0.56
    except KeyError:
        return None
    if impact == 0 and sub == 0:
        return 0.0
    return round(min(10.0, 9.3 * max(impact, 0.8 * sub) * (net * easy * priv * ui) ** 0.35), 1)


def score(vector: str) -> float | None:
    if vector.startswith("CVSS:3"):
        return v3(vector)
    if vector.startswith("CVSS:4"):
        return v4(vector)
    return None


LABEL_SCORE = {"CRITICAL": 9.0, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.5}


def label(s: float | None) -> str:
    if s is None:
        return "unbekannt"
    return "kritisch" if s >= 9 else "hoch" if s >= 7 else "mittel" if s >= 4 else "niedrig"
