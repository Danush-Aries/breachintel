#!/usr/bin/env python3
"""
breachintel.shodanpool — Shodan API key pool with automatic rotation.

All supplied keys have 0 QUERY credits but the endpoints we use don't need
them:
  • /shodan/host/{ip}    — full host data (ports, services, vulns, products)
  • /shodan/host/count   — result counts + facets (incl. geo:"" queries)
Both are free on any valid key. Scan credits (esp. the edu key) power
/shodan/scan on-demand. The pool tries keys in order, drops invalid ones,
and rotates past rate-limited / credit-exhausted keys.
"""

import os

import requests

import sources  # HEADERS

API = "https://api.shodan.io"

# Shodan API keys are loaded from env — never hardcoded.
#   SHODAN_KEYS     — comma-separated pool (recommended for rotation)
#   SHODAN_API_KEY  — single key (used in addition to SHODAN_KEYS, see _keys())
# See .env.example for the template.
KEYS = [k.strip() for k in os.environ.get("SHODAN_KEYS", "").split(",") if k.strip()]

_bad: set[str] = set()   # keys that returned 401/403 (invalid)


def _keys() -> list[str]:
    ks = []
    env = os.environ.get("SHODAN_API_KEY")
    if env:
        ks.append(env)
    ks += [k for k in KEYS if k not in _bad]
    return ks


def available() -> bool:
    return bool(_keys())


def _req(path: str, params: dict):
    for k in _keys():
        try:
            p = dict(params)
            p["key"] = k
            r = requests.get(f"{API}{path}", params=p, headers=sources.HEADERS, timeout=15)
            if r.status_code == 200:
                return r.json()
            if r.status_code in (401, 403):
                _bad.add(k)            # invalid key — never try again this run
                continue
            if r.status_code == 404:
                return {"error": "no information available"}
            # 429 / 5xx / credit issues → rotate to next key
        except Exception:
            continue
    return None


def host(ip: str):
    """Full Shodan host record (free lookup): ports, services, vulns, products."""
    return _req(f"/shodan/host/{ip}", {"minify": "false"})


def count(query: str, facets: str = "port:8,product:8,org:5"):
    """Result count + facets for a Shodan query (free, no query credit)."""
    return _req("/shodan/host/count", {"query": query, "facets": facets})


def geo_count(lat: float, lon: float, radius_km: float):
    """Device count + facets within a geographic radius (km)."""
    radius = round(min(max(radius_km, 0.1), 5), 2)   # Shodan rejects trailing-zero decimals
    return count(f'geo:"{lat},{lon},{radius:g}"')


if __name__ == "__main__":
    import json
    print("keys available:", len(_keys()))
    print(json.dumps(geo_count(40.758, -73.9855, 1), indent=2)[:400])
