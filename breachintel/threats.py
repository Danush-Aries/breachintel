#!/usr/bin/env python3
"""
breachintel.threats — real-time global threat feed (keyless).

Aggregates live malware / botnet infrastructure from abuse.ch and geolocates it
for the map + a streaming ticker:

  • URLhaus       — freshly-submitted malware-distribution URLs (per-minute)
  • Feodo Tracker — active botnet C2 servers (Emotet/Dridex/QakBot/…)

IPs are geolocated in one ip-api.com batch call (keyless). No API keys.
"""

import re
import time
from urllib.parse import urlparse

import requests

import sources  # HEADERS

URLHAUS_RECENT = "https://urlhaus.abuse.ch/downloads/json_recent/"
FEODO_C2 = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_cache = {"ts": 0.0, "data": []}


def _is_ip(h: str) -> bool:
    return bool(h and _IP_RE.match(h))


def _urlhaus(limit: int = 90) -> list[dict]:
    out = []
    try:
        r = requests.get(URLHAUS_RECENT, headers=sources.HEADERS, timeout=15)
        data = r.json()
    except Exception:
        return []
    # data: { id: [entry, ...] } newest first
    for _id, arr in data.items():
        e = arr[0] if isinstance(arr, list) and arr else arr
        if not isinstance(e, dict):
            continue
        if e.get("url_status") != "online":
            continue
        host = (urlparse(e.get("url", "")).hostname or "").lower()
        if not host:
            continue
        tags = e.get("tags") or []
        malware = (tags[0] if tags else "") or e.get("threat", "malware")
        out.append({
            "type": "malware_url", "kind": "Malware URL",
            "malware": str(malware).replace("_", " ")[:24],
            "host": host, "ip": host if _is_ip(host) else None,
            "url": e.get("url", ""), "ref": e.get("urlhaus_reference", ""),
            "date": e.get("dateadded", ""), "severity": "high",
        })
        if len(out) >= limit:
            break
    return out


def _feodo() -> list[dict]:
    out = []
    try:
        r = requests.get(FEODO_C2, headers=sources.HEADERS, timeout=15)
        data = r.json()
    except Exception:
        return []
    for e in data:
        ip = e.get("ip_address")
        if not ip:
            continue
        out.append({
            "type": "botnet_c2", "kind": "Botnet C2",
            "malware": e.get("malware", "C2"),
            "host": ip, "ip": ip,
            "url": f"https://feodotracker.abuse.ch/browse.php?search={ip}",
            "ref": "", "asn": e.get("as_name", ""),
            "country_code": (e.get("country") or "").upper(),
            "date": e.get("last_online") or e.get("first_seen", ""),
            "severity": "critical",
        })
    return out


def _geo_batch(ips: list[str]) -> dict:
    out = {}
    uniq = list({ip for ip in ips if ip})
    for i in range(0, len(uniq), 100):
        chunk = uniq[i:i + 100]
        try:
            r = requests.post(
                "http://ip-api.com/batch?fields=status,country,countryCode,lat,lon,as,query",
                json=chunk, headers=sources.HEADERS, timeout=15)
            for rec in r.json():
                if rec.get("status") == "success":
                    out[rec["query"]] = rec
        except Exception:
            pass
    return out


def feed(max_age: int = 90) -> list[dict]:
    """Aggregated, geolocated, de-duplicated live threat feed (cached briefly)."""
    now = time.time()
    if _cache["data"] and now - _cache["ts"] < max_age:
        return _cache["data"]

    items = _feodo() + _urlhaus()
    geo = _geo_batch([i["ip"] for i in items if i.get("ip")])

    seen, located = set(), []
    for it in items:
        g = geo.get(it.get("ip"))
        if g:
            it["country_code"] = it.get("country_code") or (g.get("countryCode") or "").upper()
            it["country"] = g.get("country", "")
            it["lat"] = g.get("lat")
            it["lon"] = g.get("lon")
            it["asn"] = it.get("asn") or g.get("as", "")
        if it.get("lat") is None or it.get("lon") is None:
            continue
        key = (it["type"], it.get("ip"), it.get("url"))
        if key in seen:
            continue
        seen.add(key)
        located.append(it)

    located.sort(key=lambda x: x.get("date", ""), reverse=True)
    located = located[:150]
    _cache.update(ts=now, data=located)
    return located


if __name__ == "__main__":
    import json
    import sys
    f = feed()
    print(f"{len(f)} live threats")
    print(json.dumps(f[:5], indent=2))
