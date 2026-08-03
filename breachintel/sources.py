#!/usr/bin/env python3
"""
breachintel.sources — free / no-key breach & ransomware data layer.

Every scanner returns a list of normalized Finding dicts:
    {source, category, severity, title, detail, country, date, url}

No API keys are required for any function here. Keyed sources (LeakIX,
DeHashed, IntelX, HIBP domain search) are intentionally excluded; if an env
key is present they activate as a graceful bonus, otherwise they are skipped.
"""

import os
import re
import time
import socket
import concurrent.futures
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, quote_plus
from datetime import datetime

import requests

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
HEADERS = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}

RANSOMLOOK_API = "https://www.ransomlook.io/api"
RANSOMWARE_LIVE_API = "https://api-pro.ransomware.live"
HIBP_API = "https://haveibeenpwned.com/api/v3"

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ─── helpers ──────────────────────────────────────────────────────────────────

def extract_domain(url: str) -> str:
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    d = (parsed.netloc or parsed.path).split(":")[0]
    if d.startswith("www."):
        d = d[4:]
    return d.lower()


def _get(url, timeout=15, headers=None):
    h = dict(HEADERS)
    if headers:
        h.update(headers)
    try:
        return requests.get(url, headers=h, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return None


def fmt_date(s: str) -> str:
    if not s:
        return ""
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).strftime("%Y-%m-%d")
    except Exception:
        return str(s)[:10]


def _finding(source, category, severity, title, detail="", country="", date="", url=""):
    return {
        "source": source, "category": category, "severity": severity,
        "title": title, "detail": detail, "country": country,
        "date": date, "url": url,
    }


# ─── ransomware leak trackers (free, no key) ──────────────────────────────────

def ransomware_live(domain: str) -> list[dict]:
    """api-pro.ransomware.live — victim feed + group lookup.

    Requires a free key from https://www.ransomware.live/my/
    Set RANSOMWARE_LIVE_KEY env var. Skips gracefully without it.

    Verified endpoints (2026-06):
      GET /victims/recent   → {count, victims:[{victim,group,country,activity,website,discovered,post_url,...}]}
      GET /groups           → {count, groups:[...]}
      GET /groups/<name>    → single group detail
    """
    rl_key = os.environ.get("RANSOMWARE_LIVE_KEY")
    if not rl_key:
        return []

    out, seen = [], set()
    root = domain.split(".")[0].lower()
    rl_headers = {"X-Api-Key": rl_key}

    def add(v):
        group = v.get("group") or v.get("group_name") or "?"
        victim = v.get("victim") or v.get("name") or domain
        k = (group, victim)
        if k in seen:
            return
        seen.add(k)
        out.append(_finding(
            "Ransomware.live", "ransomware", "critical",
            f"{group} → {victim}",
            f"Industry: {v.get('activity') or '?'} | {(v.get('description') or '')[:140]}",
            country=(v.get("country") or "").upper(),
            date=fmt_date(v.get("discovered") or v.get("attackdate") or v.get("published")),
            url=v.get("post_url") or v.get("permalink") or "https://www.ransomware.live/",
        ))

    # Scan recent victims feed and match domain root or website
    r = _get(f"{RANSOMWARE_LIVE_API}/victims/recent", headers=rl_headers)
    if r and r.status_code == 200:
        try:
            for v in (r.json().get("victims") or []):
                name = (v.get("victim") or "").lower()
                site = (v.get("website") or "").lower()
                if root in name or domain in site or root in site:
                    add(v)
        except Exception:
            pass

    return out


def ransomlook(domain: str) -> list[dict]:
    """ransomlook.io — search + recent posts feed across ransomware groups."""
    out, seen = [], set()
    root = domain.split(".")[0].lower()
    variants = {root, root.replace("-", ""), root.replace("_", "")}

    def add(group, title, desc, link, country="", date=""):
        key = (group, title)
        if key in seen:
            return
        seen.add(key)
        url = link if str(link).startswith("http") else f"https://www.ransomlook.io{link}"
        out.append(_finding(
            "RansomLook", "ransomware", "critical",
            f"{group} → {title}", str(desc)[:160],
            country=country.upper(), date=fmt_date(date), url=url,
        ))

    # 1) direct victim search — /api/search?q=<term> -> {groups, markets, posts}
    r = _get(f"{RANSOMLOOK_API}/search?q={quote_plus(root)}")
    if r and r.status_code == 200:
        try:
            posts = r.json().get("posts", [])
            for p in (posts or []):
                if not isinstance(p, dict):
                    continue
                title = (p.get("post_title", p.get("title", "")) or "")
                desc = (p.get("description", "") or "")
                # keep only posts that actually reference the target
                if any(v in (title + " " + desc).lower() for v in variants):
                    add(p.get("group_name", "?"), title, desc, p.get("link", ""),
                        p.get("country", ""), p.get("discovered", ""))
        except Exception:
            pass

    # 2) recent posts feed, match company variants
    r = _get(f"{RANSOMLOOK_API}/recent")
    if r and r.status_code == 200:
        try:
            for p in r.json():
                title = (p.get("post_title", "") or "").lower()
                desc = (p.get("description", "") or "").lower()
                if any(v in title or v in desc for v in variants):
                    add(p.get("group_name", "?"), p.get("post_title", ""),
                        p.get("description", ""), p.get("link", ""),
                        p.get("country", ""), p.get("discovered", ""))
        except Exception:
            pass
    return out


# ─── breach databases (free / keyless) ────────────────────────────────────────

def hibp_catalog(domain: str) -> list[dict]:
    """HIBP breach catalog (keyless): breaches attributed to this domain."""
    out = []
    key = os.environ.get("HIBP_API_KEY")
    headers = {"hibp-api-key": key} if key else {}
    r = _get(f"{HIBP_API}/breaches?domain={quote_plus(domain)}", headers=headers)
    if r and r.status_code == 200:
        try:
            for b in r.json():
                pwn = b.get("PwnCount", 0)
                sev = "critical" if pwn > 1_000_000 else "high" if pwn > 10_000 else "medium"
                out.append(_finding(
                    "HIBP", "breach", sev,
                    f"{b.get('Name','?')} — {pwn:,} accounts",
                    f"Types: {', '.join(b.get('DataClasses', [])[:8])} | Verified: {b.get('IsVerified')}",
                    date=fmt_date(b.get("BreachDate")),
                    url=f"https://haveibeenpwned.com/PwnedWebsites#{b.get('Name','')}",
                ))
        except Exception:
            pass
    return out


def leakcheck_public(domain: str) -> list[dict]:
    """LeakCheck public API (keyless): credential count + exposed fields."""
    out = []
    r = _get(f"https://leakcheck.io/api/public?check={quote_plus(domain)}&type=domain")
    if r and r.status_code == 200:
        try:
            data = r.json()
            if data.get("found"):
                out.append(_finding(
                    "LeakCheck", "breach", "critical",
                    f"{data['found']:,} credentials exposed for {domain}",
                    f"Fields: {', '.join(data.get('fields', []))}",
                    url=f"https://leakcheck.io/check?q={domain}",
                ))
        except Exception:
            pass
    return out


def otx(domain: str) -> list[dict]:
    """AlienVault OTX threat-intel pulses (keyless)."""
    out = []
    r = _get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general")
    if r and r.status_code == 200:
        try:
            n = r.json().get("pulse_info", {}).get("count", 0)
            if n:
                out.append(_finding(
                    "AlienVault OTX", "threat", "high" if n >= 5 else "medium",
                    f"{n} threat-intel pulse(s) mention {domain}", "",
                    url=f"https://otx.alienvault.com/indicator/domain/{domain}",
                ))
        except Exception:
            pass
    return out


def github_repos(domain: str) -> list[dict]:
    """GitHub repo search (keyless) for breach/dump repos."""
    out = []
    company = domain.split(".")[0]
    for q in (f"{company} breach dump", f"{company} leaked credentials", f"{company} database leak"):
        r = _get(f"https://api.github.com/search/repositories?q={quote_plus(q)}&per_page=5",
                 headers={"Accept": "application/vnd.github+json"})
        if r and r.status_code == 200:
            try:
                for it in r.json().get("items", []):
                    desc = (it.get("description") or "")[:100]
                    if company.lower() in (it["full_name"] + desc).lower():
                        out.append(_finding(
                            "GitHub", "github", "high",
                            f"{it['full_name']} — {desc or 'no description'}",
                            f"Stars: {it.get('stargazers_count', 0)} | Updated: {it.get('updated_at','')[:10]}",
                            date=it.get("updated_at", "")[:10], url=it["html_url"],
                        ))
            except Exception:
                pass
        time.sleep(0.4)
    return out


def hudsonrock_infostealer(domain: str) -> list[dict]:
    """HudsonRock Cavalier (keyless) — infostealer / stealer-log infections.

    Surfaces employees & users whose machines were infected by info-stealing
    malware (RedLine, Raccoon, Lumma, etc.), exposing corporate logins. This is
    some of the highest-signal breach data available for free.
    """
    out = []
    r = _get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
             f"search-by-domain?domain={quote_plus(domain)}", timeout=18)
    if not r or r.status_code != 200:
        return []
    try:
        d = r.json()
    except Exception:
        return []

    emp = d.get("employees", 0) or 0
    usr = d.get("users", 0) or 0
    tp = d.get("third_parties", 0) or 0
    total_stealers = d.get("totalStealers", 0) or 0
    families = d.get("stealerFamilies")
    fam_str = ", ".join(families[:5]) if isinstance(families, list) and families else "?"
    last = d.get("last_employee_compromised") or d.get("last_user_compromised") or ""

    if emp or usr:
        out.append(_finding(
            "HudsonRock", "infostealer", "critical",
            f"{emp:,} employees + {usr:,} users compromised by infostealer malware",
            f"Third-party exposure: {tp:,} | Stealer infections: {total_stealers:,} | "
            f"Families: {fam_str} | Last seen: {fmt_date(last)}",
            date=fmt_date(last),
            url=f"https://www.hudsonrock.com/free-tools?domain={domain}",
        ))

    data = d.get("data", {}) or {}
    for u in (data.get("employees_urls") or [])[:6]:
        url = u.get("url", "")
        out.append(_finding(
            "HudsonRock", "infostealer", "high",
            f"Exposed employee access → {url[:64]}",
            f"Captured in {u.get('occurrence', 0)} stealer log(s) — corporate credential at risk",
            url=url,
        ))
    return out


def proxynova_comb(domain: str) -> list[dict]:
    """ProxyNova COMB (keyless) — plaintext credential leak search (email:password)."""
    out = []
    r = _get(f"https://api.proxynova.com/comb?query={quote_plus('@' + domain)}&limit=30", timeout=14)
    if not r or r.status_code != 200:
        return []
    try:
        data = r.json()
    except Exception:
        return []
    lines = data.get("lines", []) or []
    count = data.get("count", len(lines))
    if not count:
        return []

    samples = []
    for ln in lines[:4]:
        if ":" in ln:
            u, p = ln.split(":", 1)
            samples.append(f"{u}:{p[:2]}{'•' * max(1, len(p) - 2)}")
    out.append(_finding(
        "ProxyNova COMB", "breach", "critical",
        f"{count:,}+ plaintext credentials exposed for @{domain}",
        "Masked samples: " + "; ".join(samples) if samples else "Credential pairs found in COMB dataset",
        url="https://www.proxynova.com/tools/comb/",
    ))
    return out


# Camera / DVR / IoT ports commonly left exposed (for target-scoped recon only)
_CAM_PORTS = {
    554: "RTSP stream", 8554: "RTSP-alt", 37777: "Dahua DVR", 37778: "Dahua-alt",
    34567: "Sofia/DVR", 8000: "Hikvision SDK", 8200: "Hikvision-alt",
    88: "Hikvision web", 81: "webcam HTTP", 8081: "webcam HTTP", 9000: "IP camera",
    10554: "RTSP-alt", 5543: "RTSP-alt",
}


def shodan_internetdb(domain: str) -> list[dict]:
    """Shodan InternetDB (keyless) — exposed ports, CVEs + camera/IoT on the live host."""
    out = []
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return []
    r = _get(f"https://internetdb.shodan.io/{ip}", timeout=12)
    if not r or r.status_code != 200:
        return []
    try:
        d = r.json()
    except Exception:
        return []

    vulns = d.get("vulns", []) or []
    ports = d.get("ports", []) or []
    tags = d.get("tags", []) or []

    if vulns:
        out.append(_finding(
            "Shodan", "exposure", "high",
            f"{len(vulns)} known CVE(s) on host {ip}",
            "CVEs: " + ", ".join(vulns[:14]),
            url=f"https://www.shodan.io/host/{ip}",
        ))

    # camera / IoT exposure on the TARGET's own infrastructure (authorized recon)
    cam_ports = [p for p in ports if p in _CAM_PORTS]
    if cam_ports or "webcam" in tags or "ics" in tags or "iot" in tags:
        detail = "Ports: " + ", ".join(f"{p} ({_CAM_PORTS.get(p, '?')})" for p in cam_ports)
        if tags:
            detail += f" | Shodan tags: {', '.join(tags[:6])}"
        out.append(_finding(
            "Shodan", "exposure", "high",
            f"Exposed camera / IoT service on {domain} ({ip})",
            detail or "Internet-facing camera/IoT device — review exposure & default creds.",
            url=f"https://www.shodan.io/host/{ip}",
        ))

    if ports:
        out.append(_finding(
            "Shodan", "exposure", "medium" if len(ports) < 8 else "high",
            f"{len(ports)} exposed service port(s) on {ip}",
            "Ports: " + ", ".join(map(str, sorted(ports)[:25])),
            url=f"https://www.shodan.io/host/{ip}",
        ))
    return out


def urlscan_io(domain: str) -> list[dict]:
    """URLScan.io (keyless) — observed hosting + brand-impersonation / clone detection."""
    out = []
    r = _get(f"https://urlscan.io/api/v1/search/?q=domain:{quote_plus(domain)}&size=20", timeout=15)
    if not r or r.status_code != 200:
        return []
    try:
        results = r.json().get("results", []) or []
    except Exception:
        return []

    seen_hosts = set()
    for res in results:
        page = res.get("page", {}) or {}
        url = page.get("url", "")
        ptr_domain = (page.get("domain", "") or "").lower()
        host = urlparse(url).netloc.lower()
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)

        # impersonation heuristic: page domain contains brand but is NOT the real domain
        root = domain.split(".")[0].lower()
        is_clone = root in ptr_domain and not ptr_domain.endswith(domain)
        if is_clone:
            out.append(_finding(
                "URLScan.io", "phishing", "high",
                f"Possible brand impersonation: {ptr_domain}",
                f"Hosted in {page.get('country', '?')} on {page.get('ip', '?')} ({page.get('server', '?')})",
                country=(page.get("country", "") or "").upper(),
                date=fmt_date(res.get("task", {}).get("time", "")),
                url=res.get("result", url),
            ))
        if len(out) >= 8:
            break
    return out


def _doh(name: str, rtype: str = "A") -> dict:
    """Cloudflare DNS-over-HTTPS (keyless)."""
    try:
        r = requests.get("https://cloudflare-dns.com/dns-query",
                         params={"name": name, "type": rtype},
                         headers={"accept": "application/dns-json", **HEADERS}, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def dns_posture(domain: str) -> list[dict]:
    """DNS / email security posture (keyless DoH) — SPF, DMARC, MX spoofability."""
    out = []
    txt = [a.get("data", "") for a in _doh(domain, "TXT").get("Answer", [])]
    spf = next((t for t in txt if "v=spf1" in t.lower()), None)
    dmarc_txt = [a.get("data", "") for a in _doh("_dmarc." + domain, "TXT").get("Answer", [])]
    dmarc = next((t for t in dmarc_txt if "v=dmarc1" in t.lower()), None)
    mx = _doh(domain, "MX").get("Answer", [])

    if mx and not spf:
        out.append(_finding(
            "DNS Posture", "posture", "medium",
            f"No SPF record — {domain} email is spoofable",
            "Mail domain has no SPF policy; attackers can forge sender addresses for phishing.",
            url=f"https://mxtoolbox.com/spf.aspx?domain={domain}",
        ))
    if not dmarc:
        out.append(_finding(
            "DNS Posture", "posture", "high" if mx else "medium",
            f"No DMARC record — {domain} can be impersonated in phishing",
            "No DMARC policy published; recipients cannot reject forged mail from this domain.",
            url=f"https://mxtoolbox.com/dmarc.aspx?domain={domain}",
        ))
    elif "p=none" in dmarc.lower():
        out.append(_finding(
            "DNS Posture", "posture", "medium",
            f"DMARC is monitor-only (p=none) on {domain}",
            f"Policy does not block spoofed mail: {dmarc[:120]}",
            url=f"https://mxtoolbox.com/dmarc.aspx?domain={domain}",
        ))
    return out


def _typo_candidates(domain: str) -> set:
    root, _, tld = domain.partition(".")
    if not tld or len(root) < 3:
        return set()
    perms = set()
    # omission
    for i in range(len(root)):
        perms.add(root[:i] + root[i + 1:])
    # adjacent transposition
    for i in range(len(root) - 1):
        perms.add(root[:i] + root[i + 1] + root[i] + root[i + 2:])
    # doubling
    for i in range(len(root)):
        perms.add(root[:i + 1] + root[i] + root[i + 1:])
    # homoglyph / leetspeak
    repl = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "g": "9"}
    for i, ch in enumerate(root):
        if ch in repl:
            perms.add(root[:i] + repl[ch] + root[i + 1:])
    perms.discard(root)
    perms.discard("")

    candidates = {f"{p}.{tld}" for p in perms}
    # TLD swaps of the real name
    for t in ("com", "net", "org", "co", "io", "xyz", "online", "site", "app", "info", "live", "shop"):
        if t != tld:
            candidates.add(f"{root}.{t}")
    candidates.discard(domain)
    return candidates


def typosquat(domain: str) -> list[dict]:
    """Lookalike / typosquat detection (keyless DoH) — registered impostor domains."""
    candidates = list(_typo_candidates(domain))
    if not candidates:
        return []
    candidates = candidates[:60]

    def _resolve(cand):
        d = _doh(cand, "A")
        ips = [a.get("data") for a in d.get("Answer", []) if a.get("type") == 1]
        return (cand, ips) if (d.get("Status") == 0 and ips) else (cand, None)

    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=14) as ex:
        for cand, ips in ex.map(_resolve, candidates):
            if ips:
                out.append(_finding(
                    "Typosquat", "phishing", "high",
                    f"Registered lookalike domain: {cand}",
                    f"Resolves to {', '.join(ips[:2])} — potential phishing / brand-impersonation infrastructure.",
                    url=f"http://{cand}",
                ))
    return out[:15]


def geo_locate(domain: str) -> dict | None:
    """Free GeoIP (ip-api.com, no key) — anchors the target's host on the map."""
    try:
        r = requests.get(f"http://ip-api.com/json/{domain}",
                         headers=HEADERS, timeout=12)
        d = r.json()
        if d.get("status") == "success":
            return {"country": d.get("countryCode", ""), "country_name": d.get("country", ""),
                    "lat": d.get("lat"), "lon": d.get("lon"),
                    "ip": d.get("query", ""), "isp": d.get("isp", "")}
    except Exception:
        pass
    return None


def crtsh(domain: str) -> list[str]:
    """crt.sh subdomain enumeration (keyless). Returns plain subdomain list."""
    for _ in range(3):
        r = _get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=25)
        if r and r.status_code == 200:
            try:
                subs = set()
                for e in r.json():
                    for name in (e.get("name_value", "") or "").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name.endswith(domain):
                            subs.add(name)
                return sorted(subs)
            except Exception:
                return []
        time.sleep(2)
    return []


# ─── breach news (free RSS feeds) ─────────────────────────────────────────────

_NEWS_FEEDS = [
    # Google News — targeted search for domain + breach keywords
    ("Google News",
     "https://news.google.com/rss/search?q={root}+%22data+breach%22+OR+%22hacked%22+OR+%22ransomware%22+OR+%22leaked%22&hl=en-US&gl=US&ceid=US:en",
     "news"),
    ("Google News (domain)",
     "https://news.google.com/rss/search?q={domain}+%22breach%22+OR+%22hack%22+OR+%22leak%22&hl=en-US&gl=US&ceid=US:en",
     "news"),
    # Security news sites — filter for domain mentions
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/",                  "news"),
    ("The Hacker News",  "https://feeds.feedburner.com/TheHackersNews",             "news"),
    ("Dark Reading",     "https://www.darkreading.com/rss_simple.asp",              "news"),
    ("Krebs on Security","https://krebsonsecurity.com/feed/",                       "news"),
    ("SecurityWeek",     "https://feeds.securityweek.com/securityweek/CdSf",        "news"),
    ("Threatpost",       "https://threatpost.com/feed/",                            "news"),
    ("CISA Alerts",      "https://www.cisa.gov/cybersecurity-advisories/all.xml",   "news"),
    ("InfoSecurity Mag", "https://www.infosecurity-magazine.com/rss/news/",         "news"),
    ("SC Media",         "https://www.scmagazine.com/feed",                         "news"),
    ("Cyberscoop",       "https://cyberscoop.com/feed/",                            "news"),
]

# High-signal breach keywords — if any appear near the domain, severity bumps up
_BREACH_KW = {"breach", "hacked", "hack", "leaked", "leak", "ransomware",
              "stolen", "exposed", "dump", "exfiltration", "intrusion",
              "compromise", "credential", "cyberattack", "incident"}


def _rss_findings(label: str, feed_url: str, domain: str, cat: str) -> list[dict]:
    """Parse one RSS/Atom feed and return findings that mention the domain."""
    root_name = domain.split(".")[0].lower()
    variants = {root_name, domain.lower(), root_name.replace("-", ""), root_name.replace("_", "")}
    out = []

    r = _get(feed_url.format(root=quote_plus(root_name), domain=quote_plus(domain)), timeout=12)
    if not r or r.status_code != 200:
        return []

    try:
        root_el = ET.fromstring(r.content)
    except ET.ParseError:
        return []

    # Support RSS 2.0 <item> and Atom <entry>
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    items = root_el.findall(".//item") or root_el.findall(".//atom:entry", ns)

    def _first(*els):
        for e in els:
            if e is not None:
                return e
        return None

    seen = set()
    for item in items[:40]:
        title_el = _first(item.find("title"), item.find("atom:title", ns))
        link_el  = _first(item.find("link"),  item.find("atom:link",  ns))
        desc_el  = _first(item.find("description"), item.find("atom:summary", ns), item.find("atom:content", ns))
        date_el  = _first(item.find("pubDate"), item.find("atom:published", ns), item.find("atom:updated", ns))

        title = (title_el.text or "").strip() if title_el is not None else ""
        link  = (link_el.text or link_el.get("href", "") if link_el is not None else "").strip()
        desc  = re.sub(r"<[^>]+>", " ", (desc_el.text or "") if desc_el is not None else "").strip()
        date  = fmt_date((date_el.text or "") if date_el is not None else "")

        combined = (title + " " + desc).lower()

        # Skip if domain/company not mentioned
        if not any(v in combined for v in variants):
            continue

        # Skip duplicates
        key = title[:80]
        if key in seen:
            continue
        seen.add(key)

        # Severity: high if breach keywords present, medium otherwise
        has_breach_kw = bool(_BREACH_KW & set(re.findall(r"\w+", combined)))
        sev = "high" if has_breach_kw else "medium"

        # Extra bump: "ransomware" or "leaked data" → critical
        if any(k in combined for k in ("ransomware", "leaked data", "data dump", "extortion")):
            sev = "critical"

        snippet = desc[:160].strip() or title
        out.append(_finding(label, cat, sev, title or link, snippet, date=date, url=link))

    return out


def latest_news(limit: int = 70) -> list[dict]:
    """Latest hacking / breach / threat news across security feeds (not domain-scoped)."""
    feeds = [(l, u, c) for (l, u, c) in _NEWS_FEEDS if "google news" not in l.lower()]
    out = []

    def _one(args):
        label, url, _cat = args
        items = []
        r = _get(url, timeout=12)
        if not r or r.status_code != 200:
            return []
        try:
            root = ET.fromstring(r.content)
        except ET.ParseError:
            return []
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        entries = root.findall(".//item")
        if not entries:
            entries = root.findall(".//atom:entry", ns)

        def _f(*els):
            for e in els:
                if e is not None:
                    return e
            return None

        for it in entries[:14]:
            t = _f(it.find("title"), it.find("atom:title", ns))
            lk = _f(it.find("link"), it.find("atom:link", ns))
            dt = _f(it.find("pubDate"), it.find("atom:published", ns), it.find("atom:updated", ns))
            ds = _f(it.find("description"), it.find("atom:summary", ns))
            title = (t.text or "").strip() if t is not None else ""
            link = ((lk.text or lk.get("href", "")) if lk is not None else "").strip()
            date = fmt_date((dt.text or "") if dt is not None else "")
            desc = re.sub(r"<[^>]+>", " ", (ds.text or "") if ds is not None else "").strip()
            if title and link:
                items.append({"source": label, "title": title, "url": link,
                              "date": date, "summary": desc[:180]})
        return items

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for items in ex.map(_one, feeds):
            out.extend(items)

    seen, dedup = set(), []
    for n in out:
        k = n["title"][:70]
        if k not in seen:
            seen.add(k)
            dedup.append(n)
    dedup.sort(key=lambda n: n.get("date", ""), reverse=True)
    return dedup[:limit]


def news_sources(domain: str) -> list[dict]:
    """Aggregate breach/hack news from multiple free RSS feeds (fetched in parallel)."""
    out, seen_titles = [], set()

    def _one(args):
        label, feed_url, cat = args
        try:
            return _rss_findings(label, feed_url, domain, cat)
        except Exception:
            return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for findings in ex.map(_one, _NEWS_FEEDS):
            for f in findings:
                key = f["title"][:80]
                if key not in seen_titles:
                    seen_titles.add(key)
                    out.append(f)
    return out


# ─── orchestrator ─────────────────────────────────────────────────────────────

# (label, callable) — every scanner is free / no-key
SCANNERS = [
    ("Ransomware.live", ransomware_live),
    ("RansomLook",      ransomlook),
    ("HIBP",            hibp_catalog),
    ("LeakCheck",       leakcheck_public),
    ("HudsonRock",      hudsonrock_infostealer),
    ("ProxyNova COMB",  proxynova_comb),
    ("Shodan",          shodan_internetdb),
    ("URLScan.io",      urlscan_io),
    ("AlienVault OTX",  otx),
    ("GitHub",          github_repos),
    ("DNS Posture",     dns_posture),
    ("Typosquat",       typosquat),
    ("News",            news_sources),
]


def compute_risk(findings: list[dict]) -> dict:
    """Aggregate findings into an at-a-glance exposure score (0–100) + verdict."""
    sev_w = {"critical": 1.0, "high": 0.6, "medium": 0.3, "low": 0.1, "info": 0.0}
    cat_w = {
        "ransomware": 30, "darkweb": 22, "infostealer": 28, "breach": 22,
        "phishing": 14, "paste": 12, "exposure": 12, "cracking": 9, "hacking": 9,
        "github": 8, "telegram": 8, "threat": 6, "posture": 5, "google": 4,
        "news": 1.5,
    }
    core, news_pts = 0.0, 0.0
    cat_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        cat = f.get("category", "")
        pts = sev_w.get(sev, 0) * cat_w.get(cat, 5)
        if cat == "news":
            news_pts += pts
        else:
            core += pts
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
    score = int(min(100, round(core + min(news_pts, 8))))

    if score >= 75:
        level, label = "critical", "Critical exposure"
    elif score >= 45:
        level, label = "high", "High exposure"
    elif score >= 20:
        level, label = "medium", "Moderate exposure"
    elif score > 0:
        level, label = "low", "Low exposure"
    else:
        level, label = "clean", "No exposure detected"

    nice = {
        "ransomware": "ransomware listing", "infostealer": "infostealer exposure",
        "breach": "breach record", "exposure": "exposed service", "phishing": "lookalike/clone",
        "github": "code-leak repo", "paste": "paste leak", "darkweb": "dark-web post",
        "telegram": "Telegram mention", "posture": "DNS/email weakness", "threat": "threat-intel hit",
    }
    drivers = []
    for cat, n in sorted(cat_counts.items(), key=lambda x: -x[1]):
        if cat in nice:
            drivers.append(f"{n} {nice[cat]}{'s' if n != 1 else ''}")
        if len(drivers) >= 4:
            break
    return {"score": score, "level": level, "label": label, "drivers": drivers}


def run_all(domain: str, progress_cb=None) -> dict:
    """Fan out every free source in parallel; return aggregated results."""
    findings: list[dict] = []
    errors: list[str] = []

    def _wrap(label, fn):
        try:
            return label, fn(domain)
        except Exception as e:  # noqa: BLE001
            return label, e

    subs: list[str] = []
    target_geo = None
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        futs = [ex.submit(_wrap, label, fn) for label, fn in SCANNERS]
        futs.append(ex.submit(lambda: ("crt.sh", crtsh(domain))))
        futs.append(ex.submit(lambda: ("geoip", geo_locate(domain))))
        for fut in concurrent.futures.as_completed(futs):
            label, res = fut.result()
            if isinstance(res, Exception):
                errors.append(f"{label}: {res}")
            elif label == "crt.sh":
                subs = res
            elif label == "geoip":
                target_geo = res
            else:
                findings.extend(res)
            if progress_cb:
                progress_cb(label)

    findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))
    return {
        "domain": domain,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "findings": findings,
        "subdomains": subs,
        "target_geo": target_geo,
        "risk": compute_risk(findings),
        "errors": errors,
        "total": len(findings),
    }


if __name__ == "__main__":
    import json
    import sys
    d = extract_domain(sys.argv[1] if len(sys.argv) > 1 else "example.com")
    print(json.dumps(run_all(d), indent=2))
