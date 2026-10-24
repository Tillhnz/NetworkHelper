"""Erzeugt aus Natural Earth (Public Domain) die Weltkarte für die Oberfläche und Länder-Mittelpunkte fürs Backend.

Aufruf: python tools/build_world.py ne_50m_admin_0_countries.geojson
Ergebnis: frontend/public/world.json (vorprojizierte SVG-Pfade, Miller-Projektion) und backend/app/data/country_centroids.json
"""
import json
import math
import os
import sys

W = 1000.0
LAT_MAX, LAT_MIN = 83.0, -57.0  # Antarktis weglassen


def miller(lat):
    return 1.25 * math.log(math.tan(math.pi / 4 + 0.4 * math.radians(lat)))


Y_TOP, Y_BOT = miller(LAT_MAX), miller(LAT_MIN)
H = W * (Y_TOP - Y_BOT) / (2 * math.pi)


def project(lon, lat):
    lat = max(LAT_MIN, min(LAT_MAX, lat))
    x = (lon + 180) / 360 * W
    y = (Y_TOP - miller(lat)) / (Y_TOP - Y_BOT) * H
    return x, y


def simplify(pts, tol):
    """Douglas-Peucker."""
    if len(pts) < 3:
        return pts
    a, b = pts[0], pts[-1]
    dx, dy = b[0] - a[0], b[1] - a[1]
    norm = math.hypot(dx, dy) or 1e-9
    idx, dmax = 0, 0.0
    for i in range(1, len(pts) - 1):
        p = pts[i]
        d = abs(dy * p[0] - dx * p[1] + b[0] * a[1] - b[1] * a[0]) / norm
        if d > dmax:
            idx, dmax = i, d
    if dmax > tol:
        return simplify(pts[: idx + 1], tol)[:-1] + simplify(pts[idx:], tol)
    return [a, b]


def ring_path(ring, tol):
    pts = [project(lon, lat) for lon, lat in ring]
    if len(pts) > 3 and pts[0] == pts[-1]:
        pts = pts[:-1]
    # Geschlossener Ring: am vom Start am weitesten entfernten Punkt teilen, beide Hälften vereinfachen
    far = max(range(len(pts)), key=lambda i: math.hypot(pts[i][0] - pts[0][0], pts[i][1] - pts[0][1]))
    pts = simplify(pts[: far + 1], tol)[:-1] + simplify(pts[far:] + [pts[0]], tol)
    if len(pts) < 4:
        return ""
    area = sum(pts[i][0] * pts[i + 1][1] - pts[i + 1][0] * pts[i][1] for i in range(len(pts) - 1))
    if abs(area) < 0.15:  # winzige Inseln
        return ""
    out, last = [], None
    for x, y in pts:
        cur = (round(x, 1), round(y, 1))
        if cur != last:
            out.append(f"{cur[0]:g},{cur[1]:g}")
            last = cur
    return "M" + "L".join(out) + "Z"


def main(src):
    data = json.load(open(src, encoding="utf-8"))
    countries, centroids = [], {}
    for f in data["features"]:
        p = f["properties"]
        code = p.get("ISO_A2_EH") or p.get("ISO_A2")
        if p.get("CONTINENT") == "Antarctica":
            continue
        g = f["geometry"]
        polys = g["coordinates"] if g["type"] == "MultiPolygon" else [g["coordinates"]]
        d = "".join(ring_path(poly[0], 0.35) for poly in polys)
        if not d:
            continue
        name = p.get("NAME_DE") or p.get("NAME")
        countries.append({"c": code if code and code != "-99" else None, "n": name, "d": d})
        if code and code != "-99" and p.get("LABEL_Y") is not None:
            centroids[code] = [round(p["LABEL_Y"], 3), round(p["LABEL_X"], 3)]
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    meta = {"w": W, "h": round(H, 2), "latMax": LAT_MAX, "latMin": LAT_MIN, "projection": "miller",
            "source": "Natural Earth (public domain)"}
    with open(os.path.join(root, "frontend", "public", "world.json"), "w", encoding="utf-8") as fh:
        json.dump({"meta": meta, "countries": countries}, fh, ensure_ascii=False, separators=(",", ":"))
    with open(os.path.join(root, "backend", "app", "data", "country_centroids.json"), "w", encoding="utf-8") as fh:
        json.dump(centroids, fh, separators=(",", ":"), sort_keys=True)
    print(len(countries), "Länder,", len(centroids), "Mittelpunkte, Höhe", round(H, 1))


if __name__ == "__main__":
    main(sys.argv[1])
