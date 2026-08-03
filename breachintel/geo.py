#!/usr/bin/env python3
"""
breachintel.geo — country centroids + ASCII world-map renderer.

Plots ransomware-victim / threat-actor countries as colored markers onto an
equirectangular ASCII world map. No network, no key — a static centroid table.
"""

from rich.text import Text

# ISO-2 / common-name → (lat, lon) approximate centroid. ~120 high-traffic
# countries; ransomware feeds report ISO-2 codes or full names, so we index both.
CENTROIDS = {
    "US": (39.8, -98.6), "USA": (39.8, -98.6), "UNITED STATES": (39.8, -98.6),
    "CA": (56.1, -106.3), "CANADA": (56.1, -106.3),
    "MX": (23.6, -102.5), "MEXICO": (23.6, -102.5),
    "BR": (-14.2, -51.9), "BRAZIL": (-14.2, -51.9),
    "AR": (-38.4, -63.6), "ARGENTINA": (-38.4, -63.6),
    "CL": (-35.7, -71.5), "CHILE": (-35.7, -71.5),
    "CO": (4.6, -74.3), "COLOMBIA": (4.6, -74.3),
    "PE": (-9.2, -75.0), "PERU": (-9.2, -75.0),
    "GB": (54.0, -2.0), "UK": (54.0, -2.0), "UNITED KINGDOM": (54.0, -2.0),
    "IE": (53.1, -7.7), "IRELAND": (53.1, -7.7),
    "FR": (46.2, 2.2), "FRANCE": (46.2, 2.2),
    "DE": (51.2, 10.4), "GERMANY": (51.2, 10.4),
    "ES": (40.5, -3.7), "SPAIN": (40.5, -3.7),
    "PT": (39.4, -8.2), "PORTUGAL": (39.4, -8.2),
    "IT": (41.9, 12.6), "ITALY": (41.9, 12.6),
    "NL": (52.1, 5.3), "NETHERLANDS": (52.1, 5.3),
    "BE": (50.5, 4.5), "BELGIUM": (50.5, 4.5),
    "CH": (46.8, 8.2), "SWITZERLAND": (46.8, 8.2),
    "AT": (47.5, 14.6), "AUSTRIA": (47.5, 14.6),
    "SE": (60.1, 18.6), "SWEDEN": (60.1, 18.6),
    "NO": (60.5, 8.5), "NORWAY": (60.5, 8.5),
    "FI": (61.9, 25.7), "FINLAND": (61.9, 25.7),
    "DK": (56.3, 9.5), "DENMARK": (56.3, 9.5),
    "PL": (51.9, 19.1), "POLAND": (51.9, 19.1),
    "CZ": (49.8, 15.5), "CZECHIA": (49.8, 15.5), "CZECH REPUBLIC": (49.8, 15.5),
    "RO": (45.9, 24.9), "ROMANIA": (45.9, 24.9),
    "GR": (39.1, 21.8), "GREECE": (39.1, 21.8),
    "UA": (48.4, 31.2), "UKRAINE": (48.4, 31.2),
    "RU": (61.5, 105.3), "RUSSIA": (61.5, 105.3),
    "TR": (39.0, 35.2), "TURKEY": (39.0, 35.2), "TÜRKIYE": (39.0, 35.2),
    "IL": (31.0, 34.8), "ISRAEL": (31.0, 34.8),
    "SA": (23.9, 45.1), "SAUDI ARABIA": (23.9, 45.1),
    "AE": (23.4, 53.8), "UAE": (23.4, 53.8), "UNITED ARAB EMIRATES": (23.4, 53.8),
    "IN": (20.6, 79.0), "INDIA": (20.6, 79.0),
    "PK": (30.4, 69.3), "PAKISTAN": (30.4, 69.3),
    "CN": (35.9, 104.2), "CHINA": (35.9, 104.2),
    "JP": (36.2, 138.3), "JAPAN": (36.2, 138.3),
    "KR": (35.9, 127.8), "SOUTH KOREA": (35.9, 127.8), "KOREA": (35.9, 127.8),
    "TW": (23.7, 121.0), "TAIWAN": (23.7, 121.0),
    "HK": (22.3, 114.2), "HONG KONG": (22.3, 114.2),
    "SG": (1.35, 103.8), "SINGAPORE": (1.35, 103.8),
    "MY": (4.2, 101.9), "MALAYSIA": (4.2, 101.9),
    "ID": (-0.8, 113.9), "INDONESIA": (-0.8, 113.9),
    "TH": (15.9, 100.9), "THAILAND": (15.9, 100.9),
    "VN": (14.1, 108.3), "VIETNAM": (14.1, 108.3),
    "PH": (12.9, 121.8), "PHILIPPINES": (12.9, 121.8),
    "AU": (-25.3, 133.8), "AUSTRALIA": (-25.3, 133.8),
    "NZ": (-40.9, 174.9), "NEW ZEALAND": (-40.9, 174.9),
    "ZA": (-30.6, 22.9), "SOUTH AFRICA": (-30.6, 22.9),
    "NG": (9.1, 8.7), "NIGERIA": (9.1, 8.7),
    "EG": (26.8, 30.8), "EGYPT": (26.8, 30.8),
    "KE": (-0.0, 37.9), "KENYA": (-0.0, 37.9),
    "MA": (31.8, -7.1), "MOROCCO": (31.8, -7.1),
}

# Compact equirectangular landmass sketch. 60 cols × 20 rows.
WORLD = [
    "............................................................",
    ".....___....______......._____________......................",
    "..../   \\../      \\...../              \\....._......._.....",
    "...( US  )/ CANADA \\.../  EUR   RUSSIA  \\.../ \\..../  \\....",
    "....\\__ / \\___..__/....\\__ ___..______ /...\\_/....\\JP/....",
    ".......\\_..|.......|......./  \\./      \\........_..\\_/.....",
    "........(  \\.......|...../ AFR \\/ ME\\IN \\....../ \\........",
    ".........\\  \\_.....|....|      |..|     |..../SEA \\.......",
    "..........\\   \\....|....|      |..|CHINA|...|     |.......",
    "...........| BR |..|.....\\    /...\\____ /....\\___/........",
    "...........|    |.|.......\\  /......./..........._........",
    "...........\\___ /.........\\__/....../.........../AU\\......",
    "...............|...............................|    |.....",
    "................\\.............................. \\___/......",
    "..................\\.......................................",
    "...................\\_..................NZ.\\...............",
    ".........................................................",
]

SEV_MARK = {
    "critical": ("◉", "bright_red"),
    "high": ("●", "red"),
    "medium": ("●", "yellow"),
    "low": ("•", "cyan"),
    "info": ("·", "dim"),
}


def _cell(lat, lon, rows, cols):
    col = int((lon + 180) / 360 * (cols - 1))
    row = int((90 - lat) / 180 * (rows - 1))
    return max(0, min(rows - 1, row)), max(0, min(cols - 1, col))


def render_map(findings: list[dict], target_geo: dict | None = None) -> Text:
    """Overlay victim-country markers (+ optional target anchor) on the map."""
    rows = len(WORLD)
    cols = max(len(r) for r in WORLD)
    grid = [list(r.ljust(cols)) for r in WORLD]
    style = [[None] * cols for _ in range(rows)]

    # aggregate hits + worst severity per country
    by_country: dict[str, list[str]] = {}
    for f in findings:
        c = (f.get("country") or "").strip().upper()
        if c and c in CENTROIDS:
            by_country.setdefault(c, []).append(f.get("severity", "info"))

    for country, sevs in by_country.items():
        lat, lon = CENTROIDS[country]
        r, c = _cell(lat, lon, rows, cols)
        worst = min(sevs, key=lambda s: ["critical", "high", "medium", "low", "info"].index(s)
                    if s in ["critical", "high", "medium", "low", "info"] else 4)
        mark, color = SEV_MARK.get(worst, SEV_MARK["info"])
        grid[r][c] = mark
        style[r][c] = f"bold {color}"

    # target host anchor (exact GeoIP coords)
    if target_geo and target_geo.get("lat") is not None:
        r, c = _cell(target_geo["lat"], target_geo["lon"], rows, cols)
        grid[r][c] = "⊕"
        style[r][c] = "bold bright_white"

    out = Text()
    out.append("  ┌─ GLOBAL THREAT MAP " + "─" * (cols - 19) + "┐\n", style="dim cyan")
    for r in range(rows):
        out.append("  │", style="dim cyan")
        for c in range(cols):
            ch = grid[r][c]
            if style[r][c]:
                out.append(ch, style=style[r][c])
            else:
                out.append(ch, style="grey37" if ch not in "." else "grey15")
        out.append("│\n", style="dim cyan")
    out.append("  └" + "─" * (cols + 1) + "┘\n", style="dim cyan")

    # legend
    if target_geo and target_geo.get("lat") is not None:
        out.append("  ⊕ TARGET HOST: ", style="bold bright_white")
        out.append(f"{target_geo.get('country_name','?')} ({target_geo.get('country','?')}) "
                   f"{target_geo.get('ip','')} {target_geo.get('isp','')}\n", style="white")
    if by_country:
        out.append("  Victims by country: ", style="dim")
        for country, sevs in sorted(by_country.items(), key=lambda kv: -len(kv[1])):
            mark, color = SEV_MARK.get(
                min(sevs, key=lambda s: ["critical", "high", "medium", "low", "info"].index(s)
                    if s in ["critical", "high", "medium", "low", "info"] else 4),
                SEV_MARK["info"])
            out.append(f"{mark} {country}×{len(sevs)}  ", style=color)
        out.append("\n")
    elif not target_geo:
        out.append("  No geolocated points to plot.\n", style="dim")
    return out


if __name__ == "__main__":
    from rich.console import Console
    demo = [
        {"country": "US", "severity": "critical"},
        {"country": "US", "severity": "high"},
        {"country": "DE", "severity": "high"},
        {"country": "IN", "severity": "medium"},
        {"country": "AU", "severity": "critical"},
        {"country": "BR", "severity": "high"},
    ]
    Console().print(render_map(demo))
