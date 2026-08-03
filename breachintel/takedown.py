#!/usr/bin/env python3
"""
breachintel.takedown — hosting & abuse intelligence + takedown report generation.

For every exposure that has a URL (leak sites, paste sites, dark-web mirrors,
infostealer portals, repos), this module answers the question law enforcement
and abuse teams actually need: **where is it hosted, and who do I contact to
take it down?**

Pipeline per exposure host:
    URL → hostname → IP (DNS) → GeoIP + ASN/ISP (ip-api batch, keyless)
                              → network owner + abuse email (RDAP, keyless)
    domain → registrar abuse email (RDAP, keyless)

It then renders a formal, ready-to-send takedown dossier grouping every
exposure under its hosting provider with the correct abuse contact.
"""

import socket
import concurrent.futures
from urllib.parse import urlparse
from datetime import datetime

import requests

import sources  # reuse HEADERS / UA

HEADERS = sources.HEADERS

# Categories that represent an actual hostable exposure worth a takedown.
TAKEDOWN_CATEGORIES = {
    "ransomware", "breach", "leak", "paste", "darkweb",
    "github", "telegram", "cracking", "hacking", "infostealer", "phishing",
}

# Hosts that are aggregators / news / search — never the takedown target itself.
# (Matched as substrings; GitHub is intentionally absent — leaked repos are
#  themselves takedown targets via GitHub abuse/DMCA.)
_SKIP_HOST_SUFFIXES = (
    "google.com", "bing.com", "duckduckgo.com", "brave.com",
    "bleepingcomputer.com", "thehackernews.com", "krebsonsecurity.com",
    "securityweek.com", "darkreading.com", "haveibeenpwned.com",
    "infosecurity-magazine.com", "scmagazine.com", "cyberscoop.com",
    "threatpost.com", "cisa.gov", "feedburner.com",
    "hudsonrock.com", "proxynova.com", "shodan.io", "ransomware.live",
    "ransomlook.io", "otx.alienvault.com", "leakcheck.io",
)


# ─── primitives ───────────────────────────────────────────────────────────────

def host_of(url: str) -> str | None:
    if not url:
        return None
    try:
        netloc = urlparse(url if "://" in url else "http://" + url).netloc
        host = netloc.split("@")[-1].split(":")[0].strip().lower()
        return host or None
    except Exception:
        return None


def _should_skip(host: str) -> bool:
    return any(s in host for s in _SKIP_HOST_SUFFIXES)


def _resolve_ip(host: str) -> str | None:
    # .onion has no clearnet DNS — flag it as Tor-hosted
    if host.endswith(".onion"):
        return "TOR"
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def _geoip_batch(ips: list[str]) -> dict:
    """ip-api.com batch (keyless) — {ip: {...geo+asn...}}."""
    real = [ip for ip in ips if ip and ip != "TOR"]
    out = {}
    if not real:
        return out
    # ip-api batch caps at 100 per request
    for i in range(0, len(real), 100):
        chunk = real[i:i + 100]
        try:
            r = requests.post(
                "http://ip-api.com/batch?fields=status,country,countryCode,lat,lon,isp,org,as,query",
                json=chunk, headers=HEADERS, timeout=15,
            )
            for rec in r.json():
                if rec.get("status") == "success":
                    out[rec["query"]] = rec
        except Exception:
            pass
    return out


def _rdap_ip_abuse(ip: str) -> tuple[str | None, str | None, str | None]:
    """RDAP for an IP → (network_name, abuse_email, country)."""
    if not ip or ip == "TOR":
        return (None, None, None)
    try:
        r = requests.get(f"https://rdap.org/ip/{ip}", headers=HEADERS,
                         timeout=12, allow_redirects=True)
        if r.status_code != 200:
            return (None, None, None)
        d = r.json()
        name = d.get("name")
        country = d.get("country")
        abuse = _walk_abuse_email(d.get("entities", []))
        return (name, abuse, country)
    except Exception:
        return (None, None, None)


def _rdap_domain_abuse(domain: str) -> str | None:
    """RDAP for a domain → registrar abuse email."""
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", headers=HEADERS,
                         timeout=12, allow_redirects=True)
        if r.status_code != 200:
            return None
        d = r.json()
        for e in d.get("entities", []):
            if "registrar" in e.get("roles", []):
                email = _walk_abuse_email([e])
                if email:
                    return email
        return _walk_abuse_email(d.get("entities", []))
    except Exception:
        return None


def _walk_abuse_email(entities: list) -> str | None:
    for e in entities or []:
        if "abuse" in e.get("roles", []):
            for item in e.get("vcardArray", [[], []])[1]:
                if item and item[0] == "email":
                    return item[3]
        found = _walk_abuse_email(e.get("entities", []))
        if found:
            return found
    return None


# ─── enrichment ───────────────────────────────────────────────────────────────

def enrich_hosts(findings: list[dict], max_hosts: int = 30, log_cb=None) -> list[dict]:
    """Resolve every unique exposure host to hosting + abuse intelligence."""
    def log(m):
        if log_cb:
            log_cb(m)

    # 1. collect unique, relevant hosts
    host_to_findings: dict[str, list] = {}
    for f in findings:
        if f.get("category") not in TAKEDOWN_CATEGORIES:
            continue
        h = host_of(f.get("url", ""))
        if not h or _should_skip(h):
            continue
        host_to_findings.setdefault(h, []).append(f)
        if len(host_to_findings) >= max_hosts:
            break

    if not host_to_findings:
        return []
    log(f"resolving {len(host_to_findings)} unique exposure host(s)…")

    hosts = list(host_to_findings.keys())

    # 2. resolve IPs concurrently
    ip_map = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        futs = {ex.submit(_resolve_ip, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(futs):
            ip_map[futs[fut]] = fut.result()

    # 3. batch geoip
    geo = _geoip_batch([ip for ip in ip_map.values() if ip])
    log("geo-locating hosting infrastructure…")

    # 4. RDAP abuse per unique IP (concurrent, capped)
    unique_ips = [ip for ip in set(ip_map.values()) if ip and ip != "TOR"]
    rdap_ip = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(_rdap_ip_abuse, ip): ip for ip in unique_ips[:max_hosts]}
        for fut in concurrent.futures.as_completed(futs):
            rdap_ip[futs[fut]] = fut.result()
    log("querying RDAP for network abuse contacts…")

    # 5. registrar abuse per unique registrable domain (concurrent, capped)
    reg_domains = sorted({_registrable(h) for h in hosts if not h.endswith(".onion")})
    rdap_reg = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(_rdap_domain_abuse, d): d for d in reg_domains[:max_hosts]}
        for fut in concurrent.futures.as_completed(futs):
            rdap_reg[futs[fut]] = fut.result()

    # 6. assemble records
    records = []
    for host in hosts:
        ip = ip_map.get(host)
        is_tor = ip == "TOR"
        g = geo.get(ip, {}) if ip and not is_tor else {}
        net_name, abuse_email, rdap_country = rdap_ip.get(ip, (None, None, None)) if ip else (None, None, None)
        reg_abuse = rdap_reg.get(_registrable(host))
        fset = host_to_findings[host]
        worst = _worst_severity(fset)

        # drop dead records: unresolvable, not Tor, and no actionable abuse contact
        if not is_tor and not ip and not abuse_email and not reg_abuse:
            continue

        records.append({
            "host": host,
            "ip": None if is_tor else ip,
            "tor": is_tor,
            "country": g.get("country") or rdap_country or ("Tor hidden service" if is_tor else ""),
            "country_code": (g.get("countryCode") or "").upper(),
            "lat": g.get("lat"),
            "lon": g.get("lon"),
            "asn": g.get("as", ""),
            "isp": g.get("isp", ""),
            "org": g.get("org", ""),
            "network": net_name or "",
            "abuse_email": abuse_email or "",
            "registrar_abuse": reg_abuse or "",
            "severity": worst,
            "exposure_count": len(fset),
            "sample_url": fset[0].get("url", ""),
            "sources": sorted({f.get("source", "") for f in fset}),
            "titles": [f.get("title", "")[:90] for f in fset[:5]],
        })

    # worst first
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    records.sort(key=lambda r: (order.get(r["severity"], 9), -r["exposure_count"]))
    log(f"takedown intel ready — {len(records)} host(s) profiled.")
    return records


def _registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # crude eTLD handling for common two-part suffixes
    two = {"co.uk", "com.au", "co.in", "com.br", "co.jp", "org.uk", "gov.uk", "ac.uk", "co.za"}
    if ".".join(parts[-2:]) in two:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _worst_severity(findings: list[dict]) -> str:
    order = ["critical", "high", "medium", "low", "info"]
    sevs = {f.get("severity", "info") for f in findings}
    for s in order:
        if s in sevs:
            return s
    return "info"


# ─── report generation ────────────────────────────────────────────────────────

def build_report(domain: str, records: list[dict], findings: list[dict],
                 scanned_at: str = "") -> str:
    """Render a formal, send-ready takedown dossier (Markdown/plaintext)."""
    now = scanned_at or datetime.now().isoformat(timespec="seconds")
    n_crit = sum(1 for f in findings if f.get("severity") == "critical")
    n_high = sum(1 for f in findings if f.get("severity") == "high")

    L = []
    L.append("=" * 74)
    L.append("                BREACH EXPOSURE & TAKEDOWN DOSSIER")
    L.append("=" * 74)
    L.append("")
    L.append(f"  Target domain : {domain}")
    L.append(f"  Generated     : {now}")
    L.append(f"  Total findings: {len(findings)}  ({n_crit} critical, {n_high} high)")
    L.append(f"  Hosting nodes : {len(records)} distinct exposure host(s) profiled")
    L.append("")
    L.append("  PURPOSE: This dossier identifies where data/material relating to the")
    L.append("  target is exposed, the infrastructure hosting it, and the verified")
    L.append("  abuse contacts to request removal. Provide to hosting providers,")
    L.append("  domain registrars, CERTs, or law-enforcement cybercrime units.")
    L.append("")
    L.append("=" * 74)
    L.append("  SECTION 1 — HOSTING INFRASTRUCTURE & ABUSE CONTACTS")
    L.append("=" * 74)

    for i, r in enumerate(records, 1):
        L.append("")
        L.append(f"  [{i}] {r['host']}   <{r['severity'].upper()}>")
        L.append(f"      Exposures here : {r['exposure_count']}  via {', '.join(r['sources'])}")
        if r["tor"]:
            L.append("      Hosting        : TOR HIDDEN SERVICE (no clearnet host — report to")
            L.append("                       Tor abuse / law enforcement; seizure required)")
        else:
            L.append(f"      IP address     : {r['ip'] or 'unresolved'}")
            loc = r["country"] or "?"
            L.append(f"      Location       : {loc}")
            if r["asn"] or r["isp"]:
                L.append(f"      Network / ASN  : {r['asn'] or r['network']}  ({r['isp']})")
        if r["abuse_email"]:
            L.append(f"      HOST ABUSE     : {r['abuse_email']}   ← send takedown here")
        if r["registrar_abuse"]:
            L.append(f"      REGISTRAR ABUSE: {r['registrar_abuse']}")
        if not r["abuse_email"] and not r["registrar_abuse"] and not r["tor"]:
            L.append("      Abuse contact  : not published — escalate via local CERT / ICANN")
        if r["sample_url"]:
            L.append(f"      Evidence URL   : {r['sample_url']}")
        for t in r["titles"]:
            L.append(f"         · {t}")

    L.append("")
    L.append("=" * 74)
    L.append("  SECTION 2 — READY-TO-SEND TAKEDOWN REQUEST TEMPLATE")
    L.append("=" * 74)
    L.append("")
    L.append(_template_letter(domain, records))

    L.append("")
    L.append("=" * 74)
    L.append("  SECTION 3 — FULL FINDINGS INVENTORY")
    L.append("=" * 74)
    for f in findings:
        line = f"  [{f.get('severity','info').upper():8}] {f.get('source',''):16} {f.get('title','')[:80]}"
        L.append(line)
        if f.get("url"):
            L.append(f"             {f['url']}")

    L.append("")
    L.append("-" * 74)
    L.append("  Generated by BreachIntel — free/no-key OSINT. Verify before acting.")
    L.append("  UNCLASSIFIED // FOR AUTHORIZED USE ONLY")
    L.append("-" * 74)
    return "\n".join(L)


def _template_letter(domain: str, records: list[dict]) -> str:
    hosts = ", ".join(r["host"] for r in records[:6]) or domain
    contacts = sorted({r["abuse_email"] for r in records if r["abuse_email"]})
    to = contacts[0] if contacts else "[hosting provider abuse contact]"
    urls = "\n".join(f"      - {r['sample_url']}" for r in records[:8] if r["sample_url"])
    return (
        f"  To: {to}\n"
        f"  Subject: Abuse / Takedown Request — unauthorized exposure of {domain} data\n\n"
        f"  To whom it may concern,\n\n"
        f"  We are reporting content hosted on your infrastructure that exposes\n"
        f"  data and material relating to {domain} without authorization. The\n"
        f"  following resources are involved:\n\n"
        f"{urls or '      - ' + hosts}\n\n"
        f"  This material appears to facilitate unauthorized access, fraud, or the\n"
        f"  distribution of stolen data. We request its removal under your acceptable\n"
        f"  use policy and applicable law, and ask that you preserve logs relating to\n"
        f"  the account(s) responsible for any subsequent law-enforcement request.\n\n"
        f"  Please confirm receipt and the action taken.\n\n"
        f"  Regards,\n"
        f"  [Your name / organization / contact]"
    )


if __name__ == "__main__":
    import json
    import sys
    dom = sources.extract_domain(sys.argv[1] if len(sys.argv) > 1 else "example.com")
    res = sources.run_all(dom)
    recs = enrich_hosts(res["findings"], log_cb=lambda m: print(" ·", m))
    print(build_report(dom, recs, res["findings"], res["scanned_at"]))
