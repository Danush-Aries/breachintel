#!/usr/bin/env python3
"""
breachintel.recon_plus — advanced recon modules (military-grade), keyless +
Shodan key pool. New capabilities layered on the existing recon engine:

  subdomain_takeover  — dangling-CNAME takeover detection (can-i-take-over-xyz)
  cloud_assets        — S3 / GCS / Azure bucket discovery + access classification
  shodan_host_intel   — full Shodan host intel per target IP (products/vulns/banners)
  crawl_endpoints     — live endpoint + JS crawl (katana)
  exposed_services    — Shodan geo facets: cameras, databases, ICS near a point
"""

import re
import time
import socket
import subprocess
import concurrent.futures

import requests

import sources

_FP_URL = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"
_fp_cache = {"ts": 0.0, "data": []}


def _run(cmd, timeout):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout or ""
    except Exception:
        return ""


# ── subdomain takeover ──────────────────────────────────────────────────────────

def _fingerprints():
    now = time.time()
    if _fp_cache["data"] and now - _fp_cache["ts"] < 3600:
        return _fp_cache["data"]
    try:
        r = requests.get(_FP_URL, headers=sources.HEADERS, timeout=12)
        data = [f for f in r.json() if f.get("cname")]
    except Exception:
        data = []
    _fp_cache.update(ts=now, data=data)
    return data


def _cname(host):
    ans = sources._doh(host, "CNAME").get("Answer", []) or []
    return [a.get("data", "").rstrip(".").lower() for a in ans if a.get("type") == 5]


def subdomain_takeover(domain, subdomains):
    fps = _fingerprints()
    if not fps:
        return []
    subs = [s for s in (subdomains or []) if s != domain][:60]

    def _check(sub):
        cnames = _cname(sub)
        if not cnames:
            return None
        for fp in fps:
            for pat in fp.get("cname", []):
                if any(pat.lower() in c for c in cnames):
                    vulnerable = fp.get("vulnerable", False) or fp.get("status") == "Vulnerable"
                    # confirm by fetching the page for the fingerprint string
                    confirmed = False
                    fpstr = fp.get("fingerprint", "")
                    if fpstr:
                        try:
                            rr = requests.get(f"http://{sub}", headers=sources.HEADERS, timeout=8)
                            confirmed = fpstr.lower() in rr.text.lower()
                        except Exception:
                            pass
                    return {"subdomain": sub, "cname": cnames[0], "service": fp.get("service", "?"),
                            "vulnerable": bool(vulnerable), "confirmed": confirmed}
        return None

    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for r in ex.map(_check, subs):
            if r:
                out.append(r)
    out.sort(key=lambda x: (not x["confirmed"], not x["vulnerable"]))
    return out


# ── cloud asset discovery ───────────────────────────────────────────────────────

def cloud_assets(domain):
    name = domain.split(".")[0]
    suffixes = ["", "-prod", "-dev", "-staging", "-backup", "-backups", "-assets",
                "-media", "-static", "-data", "-files", "-uploads", "-public",
                "-private", "-s3", "-storage", "-cdn", "-images", "-logs", "-db"]
    names = [f"{name}{s}" for s in suffixes] + [f"{name}{s}".replace("-", "") for s in suffixes[:6]]
    names = list(dict.fromkeys(names))[:30]
    out = []

    def _probe(bucket):
        targets = [
            ("S3", f"https://{bucket}.s3.amazonaws.com"),
            ("GCS", f"https://storage.googleapis.com/{bucket}"),
            ("Azure", f"https://{bucket}.blob.core.windows.net/?comp=list"),
        ]
        for kind, url in targets:
            try:
                r = requests.get(url, headers=sources.HEADERS, timeout=8)
                sc = r.status_code
                if sc in (200, 403):
                    access = "PUBLIC (listable)" if (sc == 200 and ("<ListBucketResult" in r.text or "<EnumerationResults" in r.text or "<Contents>" in r.text)) \
                        else "exists / private" if sc == 403 else "exists"
                    return {"bucket": bucket, "provider": kind, "url": url, "status": sc, "access": access}
            except Exception:
                continue
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for r in ex.map(_probe, names):
            if r:
                out.append(r)
    out.sort(key=lambda x: 0 if "PUBLIC" in x["access"] else 1)
    return out


# ── Shodan host intel (key pool) ────────────────────────────────────────────────

def shodan_host_intel(domain, hosts=None):
    try:
        import shodanpool
    except Exception:
        return {"enabled": False, "hosts": []}
    if not shodanpool.available():
        return {"enabled": False, "hosts": []}

    targets = [domain] + [h for h in (hosts or []) if h != domain][:10]
    ipset = {}
    for h in targets:
        try:
            ipset.setdefault(socket.gethostbyname(h), h)
        except Exception:
            pass

    def _one(ip):
        d = shodanpool.host(ip)
        if not d or d.get("error"):
            return None
        products = sorted({s.get("product") for s in d.get("data", []) if s.get("product")})
        return {"ip": ip, "host": ipset[ip], "ports": sorted(d.get("ports", []) or [])[:30],
                "vulns": list(d.get("vulns", []) or [])[:14], "products": products[:12],
                "os": d.get("os"), "org": d.get("org", ""), "isp": d.get("isp", ""),
                "hostnames": (d.get("hostnames", []) or [])[:6], "tags": d.get("tags", []) or []}

    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for r in ex.map(_one, list(ipset.keys())):
            if r:
                out.append(r)
    return {"enabled": True, "hosts": out}


# ── live endpoint crawl (katana) ────────────────────────────────────────────────

def crawl_endpoints(domain):
    raw = _run(["katana", "-u", f"https://{domain}", "-d", "2", "-jc", "-silent",
                "-c", "10", "-timeout", "8"], 45)
    urls = [u.strip() for u in raw.splitlines() if u.strip().startswith("http")]
    seen, cats = set(), {"js": [], "api": [], "params": [], "admin": [], "other": []}
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        low = u.lower()
        if low.endswith(".js"):
            cats["js"].append(u)
        elif any(k in low for k in ("/api", "/v1", "/v2", "graphql", "swagger", "rest")):
            cats["api"].append(u)
        elif "?" in u and "=" in u:
            cats["params"].append(u)
        elif any(k in low for k in ("admin", "login", "dashboard", "portal", "auth")):
            cats["admin"].append(u)
        else:
            cats["other"].append(u)
    return {"total": len(seen), "categories": {k: v[:40] for k, v in cats.items() if v}}


# ── orchestrator ────────────────────────────────────────────────────────────────

def gather(domain, subdomains=None, hosts=None):
    subs = subdomains or []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        f_take = ex.submit(subdomain_takeover, domain, subs)
        f_cloud = ex.submit(cloud_assets, domain)
        f_shodan = ex.submit(shodan_host_intel, domain, subs[:10])
        f_crawl = ex.submit(crawl_endpoints, domain)
        return {
            "domain": domain,
            "takeover": f_take.result(),
            "cloud": f_cloud.result(),
            "shodan_hosts": f_shodan.result(),
            "crawl": f_crawl.result(),
        }


if __name__ == "__main__":
    import json
    import sys
    d = sources.extract_domain(sys.argv[1] if len(sys.argv) > 1 else "example.com")
    print(json.dumps(gather(d), indent=2)[:1500])
