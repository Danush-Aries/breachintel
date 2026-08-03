#!/usr/bin/env python3
"""
breachintel.ransomwatch — live ransomware-ecosystem mirror (ransomlook.io, keyless).

Recreates the core ransomlook dashboards inside BreachIntel:
  recent()  — live recent victim posts (who got published, by which group, when)
  groups()  — every tracked ransomware group
  markets() — every tracked dark-web market

All keyless. Light endpoints only (per-group detail carries base64 screenshots
and is intentionally avoided). Cached briefly so the UI can poll cheaply.
"""

import time

import requests

import sources  # HEADERS

RL = "https://www.ransomlook.io/api"
_cache: dict[str, tuple] = {}


def _cached(key: str, fn, ttl: int):
    now = time.time()
    c = _cache.get(key)
    if c and now - c[0] < ttl:
        return c[1]
    v = fn()
    _cache[key] = (now, v)
    return v


def _get_json(url: str):
    try:
        r = requests.get(url, headers=sources.HEADERS, timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def recent(limit: int = 100) -> list[dict]:
    """Live recent victim posts: {group, victim, discovered, url}."""
    def _f():
        d = _get_json(f"{RL}/recent") or []
        out = []
        for p in d:
            if not isinstance(p, dict):
                continue
            victim = p.get("post_title") or (p.get("description", "") or "")[:80] or "?"
            out.append({
                "group": p.get("group_name", "?"),
                "victim": victim,
                "discovered": (p.get("discovered", "") or "")[:19],
                "url": p.get("link", "") or "",
            })
        return out[:limit]
    return _cached("recent", _f, 40)


def groups() -> list[str]:
    """Every tracked ransomware group."""
    def _f():
        d = _get_json(f"{RL}/groups") or []
        return sorted({g for g in d if isinstance(g, str)})
    return _cached("groups", _f, 600)


def markets() -> list[str]:
    """Every tracked dark-web market."""
    def _f():
        d = _get_json(f"{RL}/markets") or []
        return sorted({m for m in d if isinstance(m, str)})
    return _cached("markets", _f, 600)


if __name__ == "__main__":
    import json
    print(json.dumps({"recent": recent()[:3], "groups": len(groups()), "markets": len(markets())}, indent=2))
