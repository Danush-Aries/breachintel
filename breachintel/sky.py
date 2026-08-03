#!/usr/bin/env python3
"""
breachintel.sky — live global situational layer (keyless).

Two free real-time feeds for the world map:
  • aircraft()  — OpenSky Network ADS-B live aircraft positions (bounded box)
  • tle()       — CelesTrak orbital elements (TLE) for live satellite tracking
                  (positions are propagated client-side with satellite.js)

No API keys. OpenSky + CelesTrak are public and free (rate-limited).
"""

import os
import math
import time

import requests

import sources  # reuse HEADERS

OPEN_SKY = "https://opensky-network.org/api/states/all"
CELESTRAK = "https://celestrak.org/NORAD/elements/gp.php"

# OpenSky "state vector" array indices
_S = {
    "icao": 0, "callsign": 1, "country": 2, "lon": 5, "lat": 6,
    "baro_alt": 7, "on_ground": 8, "velocity": 9, "heading": 10,
    "vert_rate": 11, "geo_alt": 13,
}

_tle_cache: dict[str, tuple] = {}   # group -> (timestamp, [ {name,l1,l2} ])


def aircraft(lamin: float, lomin: float, lamax: float, lomax: float, limit: int = 250) -> list[dict]:
    """Live aircraft in a lat/lon bounding box via OpenSky (keyless)."""
    try:
        r = requests.get(OPEN_SKY, params={
            "lamin": lamin, "lomin": lomin, "lamax": lamax, "lomax": lomax,
        }, headers=sources.HEADERS, timeout=16)
        states = (r.json() or {}).get("states") or []
    except Exception:
        return []

    out = []
    for s in states[:limit]:
        try:
            lat, lon = s[_S["lat"]], s[_S["lon"]]
            if lat is None or lon is None:
                continue
            out.append({
                "icao": s[_S["icao"]],
                "callsign": (s[_S["callsign"]] or "").strip() or None,
                "country": s[_S["country"]],
                "lat": lat, "lon": lon,
                "alt": s[_S["geo_alt"]] or s[_S["baro_alt"]],
                "velocity": s[_S["velocity"]],
                "heading": s[_S["heading"]],
                "vert_rate": s[_S["vert_rate"]],
                "on_ground": s[_S["on_ground"]],
            })
        except Exception:
            continue
    return out


def tle(group: str = "visual", max_age: int = 900) -> list[dict]:
    """CelesTrak TLE set for a named group (cached). Returns [{name,l1,l2}]."""
    now = time.time()
    cached = _tle_cache.get(group)
    if cached and now - cached[0] < max_age:
        return cached[1]

    sats = []
    try:
        r = requests.get(CELESTRAK, params={"GROUP": group, "FORMAT": "TLE"},
                         headers=sources.HEADERS, timeout=16)
        lines = [ln.rstrip() for ln in r.text.splitlines() if ln.strip()]
        for i in range(0, len(lines) - 2, 3):
            name, l1, l2 = lines[i].strip(), lines[i + 1], lines[i + 2]
            if l1.startswith("1 ") and l2.startswith("2 "):
                sats.append({"name": name, "l1": l1, "l2": l2})
    except Exception:
        sats = cached[1] if cached else []

    _tle_cache[group] = (now, sats)
    return sats


# Curated INTENTIONALLY-PUBLIC live webcams (landmark / traffic / nature
# broadcasts that are published for public viewing). We deliberately do NOT
# surface unsecured / exposed private cameras.
PUBLIC_CAMS = [
    {"name": "Times Square, New York", "cat": "city", "lat": 40.7580, "lon": -73.9855, "url": "https://www.earthcam.com/usa/newyork/timessquare/?cam=tsrobo1"},
    {"name": "Abbey Road, London", "cat": "landmark", "lat": 51.5320, "lon": -0.1779, "url": "https://www.abbeyroad.com/crossing"},
    {"name": "Shibuya Crossing, Tokyo", "cat": "city", "lat": 35.6595, "lon": 139.7005, "url": "https://www.youtube.com/watch?v=Wn2_T_yMNJk"},
    {"name": "Venice Grand Canal", "cat": "city", "lat": 45.4408, "lon": 12.3155, "url": "https://www.skylinewebcams.com/en/webcam/italia/veneto/venezia/canal-grande.html"},
    {"name": "Las Vegas Strip", "cat": "city", "lat": 36.1147, "lon": -115.1728, "url": "https://www.earthcam.com/usa/nevada/lasvegas/"},
    {"name": "Niagara Falls", "cat": "nature", "lat": 43.0799, "lon": -79.0747, "url": "https://www.earthcam.com/world/canada/niagarafalls/"},
    {"name": "Eiffel Tower, Paris", "cat": "landmark", "lat": 48.8584, "lon": 2.2945, "url": "https://www.skylinewebcams.com/en/webcam/france/ile-de-france/paris/tour-eiffel.html"},
    {"name": "Sydney Harbour", "cat": "city", "lat": -33.8568, "lon": 151.2153, "url": "https://www.skylinewebcams.com/en/webcam/australia/new-south-wales/sydney/sydney-harbour.html"},
    {"name": "Dubai Marina", "cat": "city", "lat": 25.0805, "lon": 55.1403, "url": "https://www.skylinewebcams.com/en/webcam/united-arab-emirates/dubai/dubai/dubai-marina.html"},
    {"name": "Times Square Traffic", "cat": "traffic", "lat": 40.7570, "lon": -73.9860, "url": "https://www.earthcam.com/usa/newyork/timessquare/"},
    {"name": "Copacabana, Rio", "cat": "nature", "lat": -22.9711, "lon": -43.1822, "url": "https://www.skylinewebcams.com/en/webcam/brasil/rio-de-janeiro/rio-de-janeiro/copacabana.html"},
    {"name": "Mount Fuji, Japan", "cat": "nature", "lat": 35.3606, "lon": 138.7274, "url": "https://www.youtube.com/watch?v=fGgZ-mZ4_2k"},
    {"name": "Red Square, Moscow", "cat": "landmark", "lat": 55.7539, "lon": 37.6208, "url": "https://www.skylinewebcams.com/en/webcam/russia/moscow.html"},
    {"name": "Golden Gate Bridge", "cat": "landmark", "lat": 37.8199, "lon": -122.4783, "url": "https://www.earthcam.com/usa/california/sanfrancisco/goldengatebridge/"},
    {"name": "Singapore Marina Bay", "cat": "city", "lat": 1.2834, "lon": 103.8607, "url": "https://www.skylinewebcams.com/en/webcam/singapore/singapore/singapore/marina-bay.html"},
    {"name": "Times Square Cafe, NYC", "cat": "city", "lat": 40.7560, "lon": -73.9870, "url": "https://www.earthcam.com/usa/newyork/timessquare/?cam=gts1"},
    {"name": "Honolulu, Waikiki Beach", "cat": "nature", "lat": 21.2767, "lon": -157.8270, "url": "https://www.earthcam.com/usa/hawaii/waikiki/"},
    {"name": "Berlin Brandenburg Gate", "cat": "landmark", "lat": 52.5163, "lon": 13.3777, "url": "https://www.earthcam.com/world/germany/berlin/"},
    {"name": "Toronto Skyline", "cat": "city", "lat": 43.6426, "lon": -79.3871, "url": "https://www.earthcam.com/world/canada/toronto/"},
    {"name": "Amsterdam Canals", "cat": "city", "lat": 52.3676, "lon": 4.9041, "url": "https://www.skylinewebcams.com/en/webcam/nederland/noord-holland/amsterdam.html"},
]


def public_cams() -> list[dict]:
    """Curated list of intentionally-public live webcams (no exposed/private cams)."""
    return PUBLIC_CAMS


# ── geo recon: location search + radius reconnaissance ──────────────────────────

def _haversine_m(lat1, lon1, lat2, lon2) -> float:
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


OVERPASS_MIRRORS = [
    "https://overpass-api.de/api/interpreter",
    "https://overpass.kumi.systems/api/interpreter",
    "https://maps.mail.ru/osm/tools/overpass/api/interpreter",
]


def osm_cameras(lat: float, lon: float, radius_m: int = 300, limit: int = 80) -> list[dict]:
    """OpenStreetMap crowd-mapped surveillance cameras (keyless). Returns the
    LOCATION + public/private classification of mapped cameras — never feeds."""
    q = (f'[out:json][timeout:25];'
         f'(node["man_made"="surveillance"](around:{radius_m},{lat},{lon}););'
         f'out body {limit};')
    els = []
    for mirror in OVERPASS_MIRRORS:
        try:
            r = requests.post(mirror, data={"data": q}, headers=sources.HEADERS, timeout=12)
            if r.status_code == 200:
                els = r.json().get("elements", [])
                break
        except Exception:
            continue
    out = []
    for e in els:
        t = e.get("tags", {})
        zone = (t.get("surveillance", "") or "").lower()
        stype = t.get("surveillance:type", "camera")
        ctype = t.get("camera:type", "")
        is_webcam = zone == "webcam"
        is_alpr = "alpr" in stype.lower() or "alpr" in ctype.lower()
        public = zone in ("public", "outdoor", "town", "street", "traffic") or is_webcam
        out.append({
            "lat": e.get("lat"), "lon": e.get("lon"),
            "zone": zone or "unspecified", "type": stype, "cam_type": ctype,
            "operator": t.get("operator", "") or t.get("brand", ""),
            "direction": t.get("direction", ""),
            "public": public, "webcam": is_webcam, "alpr": is_alpr,
        })
    return [c for c in out if c["lat"] is not None]


def reverse_geocode(lat: float, lon: float) -> str:
    try:
        r = requests.get("https://nominatim.openstreetmap.org/reverse",
                         params={"lat": lat, "lon": lon, "format": "json"},
                         headers={"User-Agent": "BreachIntel/1.0 (osint)"}, timeout=12)
        return r.json().get("display_name", "")
    except Exception:
        return ""


def geocode(q: str) -> dict:
    """Forward geocode a place name → lat/lon (OpenStreetMap Nominatim, keyless)."""
    try:
        r = requests.get("https://nominatim.openstreetmap.org/search",
                         params={"q": q, "format": "json", "limit": 1},
                         headers={"User-Agent": "BreachIntel/1.0 (osint)"}, timeout=12)
        d = r.json()
        if d:
            return {"lat": float(d[0]["lat"]), "lon": float(d[0]["lon"]), "name": d[0]["display_name"]}
    except Exception:
        pass
    return {"error": "location not found"}


def shodan_geo(lat: float, lon: float, radius_km: float) -> dict:
    """Shodan geo device discovery via the key pool's free /host/count facets.
    Returns AGGREGATE metadata only (device counts, top ports/products) —
    never camera feeds or per-device access."""
    import shodanpool
    if not shodanpool.available():
        return {"enabled": False, "note": "No Shodan key available — showing public cameras only."}
    d = shodanpool.geo_count(lat, lon, radius_km)
    if not d or d.get("error"):
        return {"enabled": False, "note": "Shodan geo query returned no data (all keys rate-limited)."}
    fac = d.get("facets", {})
    return {
        "enabled": True,
        "total": d.get("total", 0),
        "ports": [[f["value"], f["count"]] for f in fac.get("port", [])],
        "products": [[f["value"], f["count"]] for f in fac.get("product", [])],
        "orgs": [[f["value"], f["count"]] for f in fac.get("org", [])],
        "note": "Live Shodan geo metadata — device counts & exposed services. No camera feeds accessed.",
    }


def shodan_cctv(lat: float, lon: float, radius_km: float) -> dict:
    """Count internet-exposed camera devices near a point via Shodan geo facets
    (free /host/count). Aggregate counts only — no per-camera access."""
    try:
        import shodanpool
    except Exception:
        return {"enabled": False}
    if not shodanpool.available():
        return {"enabled": False}
    r = round(min(max(radius_km, 0.1), 5), 2)
    geo = f'geo:"{lat},{lon},{r:g}"'
    probes = {
        "RTSP streams (554)": "port:554",
        "Dahua DVR (37777)": "port:37777",
        "Hikvision (8000)": "port:8000",
        "Webcam HTTP (81)": "port:81",
        "MJPG streamers": 'product:"MJPG-streamer"',
    }
    out = {}
    total = 0
    for label, q in probes.items():
        d = shodanpool.count(f"{geo} {q}", facets="")
        n = (d or {}).get("total", 0) if d else 0
        if n:
            out[label] = n
            total += n
    return {"enabled": True, "total": total, "breakdown": out}


def geo_recon(lat: float, lon: float, radius_m: int = 100) -> dict:
    """Fan out every geo source at once: public cams + OSM mapped cameras
    (public/private classified) + reverse-geocode + key-gated Shodan."""
    import concurrent.futures

    cams = [{**c, "dist_m": round(_haversine_m(lat, lon, c["lat"], c["lon"]))} for c in PUBLIC_CAMS]
    cams.sort(key=lambda x: x["dist_m"])
    within = [c for c in cams if c["dist_m"] <= radius_m]

    osm_radius = max(radius_m, 200)   # widen a little so a tight circle still finds context
    km = max(0.1, radius_m / 1000.0)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        f_osm = ex.submit(osm_cameras, lat, lon, osm_radius)
        f_place = ex.submit(reverse_geocode, lat, lon)
        f_sh = ex.submit(shodan_geo, lat, lon, km)
        f_cctv = ex.submit(shodan_cctv, lat, lon, km)
        osm = f_osm.result()
        place = f_place.result()
        sh = f_sh.result()
        cctv = f_cctv.result()

    for c in osm:
        c["dist_m"] = round(_haversine_m(lat, lon, c["lat"], c["lon"]))
    osm.sort(key=lambda x: x["dist_m"])
    osm_within = [c for c in osm if c["dist_m"] <= radius_m]

    return {
        "lat": lat, "lon": lon, "radius_m": radius_m, "place": place,
        "within_count": len(within),
        "cams_within": within,
        "cams_nearest": cams[:6],
        "osm_cameras": osm,
        "osm_within": len(osm_within),
        "osm_public": sum(1 for c in osm if c["public"]),
        "osm_private": sum(1 for c in osm if not c["public"] and not c["webcam"]),
        "osm_alpr": sum(1 for c in osm if c["alpr"]),
        "shodan": sh,
        "cctv": cctv,
    }


def satellites(groups: str = "stations,visual", limit: int = 180) -> list[dict]:
    """Merge several CelesTrak groups, dedup by name, cap the count."""
    seen, out = set(), []
    for g in groups.split(","):
        for s in tle(g.strip()):
            if s["name"] in seen:
                continue
            seen.add(s["name"])
            out.append(s)
            if len(out) >= limit:
                return out
    return out
