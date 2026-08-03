#!/usr/bin/env python3
"""
breachintel.advanced — 10 differentiating intelligence modules.

Server-side half of the "Intel Modules" page. Heavily Shodan-powered (keyless
InternetDB across the WHOLE resolved IP footprint, not just the apex), plus
email-security grading, ASN bad-neighborhood scoring and typosquat triage.

The remaining modules (exposure timeline, credential index, attack-surface
index, data-class breakdown, monitoring diff) are computed client-side from
already-fetched scan/recon data.
"""

import re
import base64
import hashlib
import socket
import concurrent.futures
from urllib.parse import quote

import requests

import sources
import threats as threats_mod

INTERNETDB = "https://internetdb.shodan.io"


# ── Module 1 & 2: Shodan footprint + CVE inventory ──────────────────────────────

def _idb(ip: str) -> dict | None:
    try:
        r = requests.get(f"{INTERNETDB}/{ip}", headers=sources.HEADERS, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _host_data(ip: str) -> dict | None:
    """Per-IP exposure: prefer the Shodan key pool (richer: products/vulns),
    fall back to keyless InternetDB."""
    try:
        import shodanpool
        if shodanpool.available():
            d = shodanpool.host(ip)
            if d and not d.get("error"):
                products = sorted({s.get("product") for s in d.get("data", []) if s.get("product")})
                return {"ports": d.get("ports", []) or [], "vulns": list(d.get("vulns", []) or []),
                        "cpes": (d.get("cpes", []) or products), "tags": d.get("tags", []) or []}
    except Exception:
        pass
    return _idb(ip)


def shodan_footprint(domain: str, hosts: list[str] | None = None) -> dict:
    """Query Shodan InternetDB across the apex + sampled subdomains (keyless)."""
    targets = [domain] + [h for h in (hosts or []) if h != domain][:24]
    ipmap = {}

    def _res(h):
        try:
            return h, socket.gethostbyname(h)
        except Exception:
            return h, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for h, ip in ex.map(_res, targets):
            if ip:
                ipmap.setdefault(ip, h)

    ports, cpes, tags = {}, set(), set()
    vulns = {}
    host_recs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        results = list(ex.map(lambda ip: (ip, _host_data(ip)), list(ipmap.keys())))

    for ip, d in results:
        if not d:
            continue
        p = d.get("ports", []) or []
        v = d.get("vulns", []) or []
        for port in p:
            ports[port] = ports.get(port, 0) + 1
        for c in d.get("cpes", []) or []:
            cpes.add(c)
        for t in d.get("tags", []) or []:
            tags.add(t)
        for cve in v:
            vulns.setdefault(cve, []).append(ip)
        if p or v:
            host_recs.append({"ip": ip, "host": ipmap[ip], "ports": sorted(p)[:14],
                              "vulns": v[:8], "tags": d.get("tags", [])})

    return {
        "ip_count": len(ipmap),
        "responded": len(host_recs),
        "ports": sorted(ports.keys()),
        "port_count": len(ports),
        "services": sorted(cpes)[:40],
        "service_count": len(cpes),
        "tags": sorted(tags),
        "cves": sorted(vulns.keys()),
        "cve_count": len(vulns),
        "cve_hosts": {k: v for k, v in list(vulns.items())[:30]},
        "hosts": sorted(host_recs, key=lambda h: -len(h["vulns"]))[:30],
    }


# ── Module 3: email security scorecard ──────────────────────────────────────────

def email_scorecard(domain: str) -> dict:
    txt = [a.get("data", "") for a in sources._doh(domain, "TXT").get("Answer", [])]
    spf = next((t for t in txt if "v=spf1" in t.lower()), "")
    dmarc_ans = [a.get("data", "") for a in sources._doh("_dmarc." + domain, "TXT").get("Answer", [])]
    dmarc = next((t for t in dmarc_ans if "v=dmarc1" in t.lower()), "")
    mx = sources._doh(domain, "MX").get("Answer", [])
    mta = [a.get("data", "") for a in sources._doh("_mta-sts." + domain, "TXT").get("Answer", [])]
    bimi = sources._doh("default._bimi." + domain, "TXT").get("Answer", [])
    dnssec = bool(sources._doh(domain, "DNSKEY").get("Answer"))

    checks = []
    score = 0
    if spf:
        score += 25; checks.append(("SPF", "pass", "present"))
    else:
        checks.append(("SPF", "fail", "missing — sender spoofing possible"))
    if dmarc:
        pol = "none"
        m = re.search(r"p=(\w+)", dmarc.lower())
        if m:
            pol = m.group(1)
        if pol == "reject":
            score += 35; checks.append(("DMARC", "pass", "p=reject (strong)"))
        elif pol == "quarantine":
            score += 25; checks.append(("DMARC", "warn", "p=quarantine"))
        else:
            score += 10; checks.append(("DMARC", "warn", "p=none (monitor only)"))
    else:
        checks.append(("DMARC", "fail", "missing — domain is spoofable"))
    if mx:
        score += 10; checks.append(("MX", "pass", f"{len(mx)} mail server(s)"))
    else:
        checks.append(("MX", "warn", "no MX records"))
    if dnssec:
        score += 15; checks.append(("DNSSEC", "pass", "signed"))
    else:
        checks.append(("DNSSEC", "warn", "unsigned"))
    if any("v=STSv1" in t for t in mta):
        score += 10; checks.append(("MTA-STS", "pass", "enforced"))
    else:
        checks.append(("MTA-STS", "warn", "not configured"))
    if bimi:
        score += 5; checks.append(("BIMI", "pass", "present"))

    grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"
    return {"score": min(100, score), "grade": grade, "checks": checks}


# ── Module 4: ASN bad-neighborhood threat score ─────────────────────────────────

def _asn_num(asn: str) -> str:
    m = re.search(r"AS(\d+)", asn or "")
    return m.group(1) if m else ""


def asn_threat_score(asn: str) -> dict:
    num = _asn_num(asn)
    if not num:
        return {"asn": asn, "threats": 0, "samples": []}
    feed = threats_mod.feed()
    hits = [t for t in feed if num == _asn_num(t.get("asn", ""))]
    samples = [{"ip": t.get("ip"), "malware": t.get("malware"), "type": t.get("type"),
                "country": t.get("country_code")} for t in hits[:10]]
    return {"asn": asn, "asn_num": num, "threats": len(hits), "samples": samples}


# ── Module 8: typosquat triage (phishing capability) ────────────────────────────

def typosquat_triage(domains: list[str]) -> list[dict]:
    out = []

    def _check(dom):
        mx = sources._doh(dom, "MX").get("Answer", [])
        a = sources._doh(dom, "A").get("Answer", [])
        live = bool(a)
        mail = bool(mx)
        risk = "phishing-ready" if (live and mail) else "parked/live" if live else "registered"
        return {"domain": dom, "live": live, "mx": mail, "risk": risk,
                "ip": (a[0].get("data") if a else "")}

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        out = list(ex.map(_check, domains[:20]))
    # phishing-ready first
    order = {"phishing-ready": 0, "parked/live": 1, "registered": 2}
    out.sort(key=lambda x: order.get(x["risk"], 9))
    return out


# ── Module: favicon-hash pivot (fav-up / CloudFlare-IP technique, keyless) ──────

def _murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit (signed) — matches Shodan's http.favicon.hash."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h1 = seed
    rounded = length & 0xfffffffc
    for i in range(0, rounded, 4):
        k1 = (data[i] & 0xff) | ((data[i+1] & 0xff) << 8) | ((data[i+2] & 0xff) << 16) | (data[i+3] << 24)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1 = 0
    tail = length & 0x03
    if tail == 3:
        k1 = (data[rounded + 2] & 0xff) << 16
    if tail >= 2:
        k1 |= (data[rounded + 1] & 0xff) << 8
    if tail >= 1:
        k1 |= (data[rounded] & 0xff)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= (h1 >> 16)
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_intel(domain: str) -> dict:
    """Compute the favicon hash + pivot links to find clones / Cloudflare origin IP."""
    content = None
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{domain}/favicon.ico", headers=sources.HEADERS,
                             timeout=12, allow_redirects=True)
            if r.status_code == 200 and r.content and len(r.content) > 50:
                content = r.content
                break
        except Exception:
            continue
    if not content:
        return {"found": False}

    b64 = base64.encodebytes(content)
    mmh3 = _murmur3_32(b64)
    md5 = hashlib.md5(content).hexdigest()
    fofa_q = base64.b64encode(f'icon_hash="{mmh3}"'.encode()).decode()
    return {
        "found": True, "mmh3": mmh3, "md5": md5, "size": len(content),
        "pivots": {
            "Shodan": f"https://www.shodan.io/search?query=http.favicon.hash%3A{mmh3}",
            "FOFA": f"https://fofa.info/result?qbase64={quote(fofa_q)}",
            "ZoomEye": f"https://www.zoomeye.org/searchResult?q=iconhash%3A%22{mmh3}%22",
            "Censys": f"https://search.censys.io/search?resource=hosts&q=services.http.response.favicons.md5_hash%3A%22{md5}%22",
        },
        "note": "Hosts sharing this favicon hash are likely clones or the real origin behind Cloudflare/CDN.",
    }


# ── orchestrator ────────────────────────────────────────────────────────────────

def gather(domain: str, hosts=None, asn="", lookalikes=None) -> dict:
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        f_shodan = ex.submit(shodan_footprint, domain, hosts)
        f_email = ex.submit(email_scorecard, domain)
        f_asn = ex.submit(asn_threat_score, asn)
        f_typo = ex.submit(typosquat_triage, lookalikes or [])
        f_fav = ex.submit(favicon_intel, domain)
        return {
            "domain": domain,
            "shodan": f_shodan.result(),
            "email": f_email.result(),
            "asn_threat": f_asn.result(),
            "typosquat": f_typo.result(),
            "favicon": f_fav.result(),
        }


if __name__ == "__main__":
    import json
    import sys
    d = sources.extract_domain(sys.argv[1] if len(sys.argv) > 1 else "example.com")
    print(json.dumps(gather(d), indent=2))
