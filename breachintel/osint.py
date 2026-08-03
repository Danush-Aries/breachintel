#!/usr/bin/env python3
"""
breachintel.osint — deep OSINT dossier builder ("all-source" intelligence).

Fuses native keyless web sources with the proven OSINT CLI tools installed on
the box (subfinder, whatweb, theHarvester, sherlock) into one structured dossier:

  registration · DNS · subdomains · infrastructure/ASN · reverse-IP neighbours
  · technology stack · emails/people · certificates · username footprint

Every collector is defensive + time-bounded; missing tools degrade gracefully.
No API keys required.
"""

import os
import re
import json
import time
import socket
import shutil
import subprocess
import tempfile
import concurrent.futures
from urllib.parse import quote_plus, urlparse, parse_qs, unquote

import requests

import sources  # _doh, _get, crtsh, HEADERS

HT = "https://api.hackertarget.com"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _run(cmd: list, timeout: int) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout or ""
    except Exception:
        return ""


# ─── registration (RDAP) ───────────────────────────────────────────────────────

def registration(domain: str) -> dict:
    out = {"registrar": "", "created": "", "updated": "", "expires": "",
           "registrant": "", "nameservers": [], "status": [], "dnssec": ""}
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", headers=sources.HEADERS,
                         timeout=12, allow_redirects=True)
        if r.status_code != 200:
            return out
        d = r.json()
        ev = {e.get("eventAction"): e.get("eventDate", "")[:10] for e in d.get("events", [])}
        out["created"] = ev.get("registration", "")
        out["updated"] = ev.get("last changed", "") or ev.get("last update of RDAP database", "")
        out["expires"] = ev.get("expiration", "")
        out["status"] = d.get("status", [])
        out["nameservers"] = [ns.get("ldhName", "").lower() for ns in d.get("nameservers", [])]
        sd = d.get("secureDNS", {})
        out["dnssec"] = "signed" if sd.get("delegationSigned") else "unsigned"
        for e in d.get("entities", []):
            roles = e.get("roles", [])
            vcard = e.get("vcardArray", [None, []])[1] if e.get("vcardArray") else []
            name = next((it[3] for it in vcard if it and it[0] == "fn"), "")
            org = next((it[3] for it in vcard if it and it[0] == "org"), "")
            if "registrar" in roles:
                out["registrar"] = name or org or e.get("handle", "")
            if "registrant" in roles:
                out["registrant"] = org or name
    except Exception:
        pass
    return out


# ─── DNS records (DoH) ──────────────────────────────────────────────────────────

def dns_records(domain: str) -> dict:
    out = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"):
        ans = sources._doh(domain, rtype).get("Answer", []) or []
        vals = []
        for a in ans:
            data = a.get("data", "")
            if data and data not in vals:
                vals.append(data)
        if vals:
            out[rtype] = vals[:12]
    return out


# ─── subdomains (subfinder + hackertarget + crt.sh, merged) ─────────────────────

def subdomains(domain: str) -> list[str]:
    found = set()
    if _have("subfinder"):
        for line in _run(["subfinder", "-d", domain, "-silent"], 35).splitlines():
            s = line.strip().lower()
            if s.endswith(domain):
                found.add(s)
    try:
        r = sources._get(f"{HT}/hostsearch/?q={quote_plus(domain)}", timeout=12)
        if r and r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.splitlines():
                host = line.split(",")[0].strip().lower()
                if host.endswith(domain):
                    found.add(host)
    except Exception:
        pass
    try:
        for s in sources.crtsh(domain):
            found.add(s.lower())
    except Exception:
        pass
    return sorted(found)


# ─── infrastructure: hosts → IP, geo/ASN, reverse-IP neighbours ─────────────────

def _geo_batch(ips: list[str]) -> dict:
    out, uniq = {}, list({i for i in ips if i})
    for i in range(0, len(uniq), 100):
        try:
            r = requests.post(
                "http://ip-api.com/batch?fields=status,country,countryCode,city,isp,org,as,query",
                json=uniq[i:i + 100], headers=sources.HEADERS, timeout=15)
            for rec in r.json():
                if rec.get("status") == "success":
                    out[rec["query"]] = rec
        except Exception:
            pass
    return out


def infrastructure(domain: str, hosts: list[str]) -> dict:
    # resolve the apex + a sample of subdomains
    sample = [domain] + [h for h in hosts if h != domain][:24]
    ipmap = {}

    def _res(h):
        try:
            return h, socket.gethostbyname(h)
        except Exception:
            return h, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for h, ip in ex.map(_res, sample):
            if ip:
                ipmap[h] = ip

    geo = _geo_batch(list(ipmap.values()))
    hosts_out = []
    for h, ip in ipmap.items():
        g = geo.get(ip, {})
        hosts_out.append({"host": h, "ip": ip, "country": g.get("country", ""),
                          "cc": (g.get("countryCode") or "").upper(),
                          "asn": g.get("as", ""), "isp": g.get("isp", g.get("org", ""))})

    # reverse-IP neighbours on the apex IP (shared hosting / co-located)
    neighbours = []
    apex_ip = ipmap.get(domain)
    if apex_ip:
        try:
            r = sources._get(f"{HT}/reverseiplookup/?q={apex_ip}", timeout=12)
            if r and r.status_code == 200:
                bad = ("no dns", "error", "api count", "no records")
                neighbours = [x.strip() for x in r.text.splitlines()
                              if x.strip() and not any(b in x.lower() for b in bad)][:40]
        except Exception:
            pass

    asns = sorted({h["asn"] for h in hosts_out if h["asn"]})
    return {"hosts": hosts_out, "apex_ip": apex_ip, "asns": asns,
            "reverse_ip": {"ip": apex_ip, "neighbours": neighbours}}


# ─── full IP profile + nmap port/service scan ───────────────────────────────────

def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def ip_profile(domain: str) -> dict:
    """Complete IP intelligence: geo, ASN, PTR, netblock + abuse (RDAP)."""
    prof = {"ip": "", "ptr": "", "country": "", "city": "", "asn": "",
            "isp": "", "org": "", "lat": None, "lon": None,
            "network": "", "abuse": "", "rdap_country": ""}
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return prof
    prof["ip"] = ip
    prof["ptr"] = _reverse_dns(ip)
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}"
                         "?fields=status,country,countryCode,city,lat,lon,isp,org,as,reverse",
                         headers=sources.HEADERS, timeout=12)
        g = r.json()
        if g.get("status") == "success":
            prof.update(country=g.get("country", ""), city=g.get("city", ""),
                        asn=g.get("as", ""), isp=g.get("isp", ""), org=g.get("org", ""),
                        lat=g.get("lat"), lon=g.get("lon"))
            if not prof["ptr"]:
                prof["ptr"] = g.get("reverse", "")
    except Exception:
        pass
    # RDAP netblock + abuse contact
    try:
        import takedown
        name, abuse, country = takedown._rdap_ip_abuse(ip)
        prof["network"] = name or ""
        prof["abuse"] = abuse or ""
        prof["rdap_country"] = country or ""
    except Exception:
        pass
    return prof


def nmap_scan(domain: str, top_ports: int = 150) -> dict:
    """nmap TCP service scan of the resolved host (no root needed)."""
    out = {"ip": "", "ports": [], "ran": False}
    if not _have("nmap"):
        return out
    try:
        out["ip"] = socket.gethostbyname(domain)
    except Exception:
        return out
    raw = _run(["nmap", "-sT", "-sV", "-Pn", "--top-ports", str(top_ports),
                "-T4", "--host-timeout", "70s", "-oG", "-", out["ip"]], 80)
    out["ran"] = True
    for line in raw.splitlines():
        if "Ports:" not in line:
            continue
        portfield = line.split("Ports:", 1)[1]
        for chunk in portfield.split(","):
            parts = chunk.strip().split("/")
            if len(parts) >= 5 and parts[1] == "open":
                port, proto, svc = parts[0], parts[2], parts[4]
                ver = parts[6].strip() if len(parts) > 6 else ""
                out["ports"].append({"port": int(port), "proto": proto,
                                     "service": svc or "?", "version": ver})
    out["ports"].sort(key=lambda p: p["port"])
    return out


def web_fingerprint(domain: str) -> dict:
    """httpx — status, title, server, tech, CDN (fast web fingerprint)."""
    fp = {"status": "", "title": "", "server": "", "tech": [], "cdn": "", "webserver": ""}
    if not _have("httpx"):
        return fp
    raw = _run(["httpx", "-u", f"https://{domain}", "-json", "-silent",
                "-title", "-status-code", "-tech-detect", "-web-server",
                "-cdn", "-no-color"], 25)
    for line in raw.splitlines():
        try:
            d = json.loads(line)
            fp["status"] = str(d.get("status_code", ""))
            fp["title"] = d.get("title", "")
            fp["webserver"] = d.get("webserver", "")
            fp["tech"] = d.get("tech", []) or d.get("technologies", []) or []
            fp["cdn"] = d.get("cdn_name", "") or ("yes" if d.get("cdn") else "")
            break
        except Exception:
            continue
    return fp


def http_headers(domain: str) -> dict:
    """Fetch HTTP response headers + grade the security headers."""
    out = {"server": "", "headers": {}, "security": {}, "missing": []}
    try:
        r = requests.get(f"https://{domain}", headers=sources.HEADERS, timeout=12,
                         allow_redirects=True)
        h = {k.lower(): v for k, v in r.headers.items()}
    except Exception:
        return out
    out["server"] = h.get("server", "")
    keep = ["server", "x-powered-by", "via", "x-cache", "cf-ray", "x-amz-cf-id",
            "content-type", "set-cookie"]
    out["headers"] = {k: h[k][:80] for k in keep if k in h}
    checks = {
        "Strict-Transport-Security": "strict-transport-security",
        "Content-Security-Policy": "content-security-policy",
        "X-Frame-Options": "x-frame-options",
        "X-Content-Type-Options": "x-content-type-options",
        "Referrer-Policy": "referrer-policy",
        "Permissions-Policy": "permissions-policy",
    }
    for label, key in checks.items():
        if key in h:
            out["security"][label] = "present"
        else:
            out["missing"].append(label)
    return out


def nuclei_scan(domain: str, timeout: int = 75) -> dict:
    """Bounded nuclei scan (exposures / misconfig / CVEs, high+critical)."""
    out = {"ran": False, "findings": []}
    if not _have("nuclei"):
        return out
    out["ran"] = True
    raw = _run(["nuclei", "-u", f"https://{domain}", "-jsonl", "-silent",
                "-severity", "critical,high,medium", "-timeout", "5", "-retries", "1",
                "-rl", "150", "-no-color", "-tags", "exposure,misconfig,cve,tech,takeover"],
               timeout)
    for line in raw.splitlines():
        try:
            j = json.loads(line)
            info = j.get("info", {})
            out["findings"].append({
                "name": info.get("name", j.get("template-id", "?")),
                "severity": (info.get("severity") or "info").lower(),
                "matched": j.get("matched-at", j.get("host", "")),
                "tags": info.get("tags", [])[:5],
            })
        except Exception:
            continue
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out["findings"].sort(key=lambda f: order.get(f["severity"], 9))
    return out


def waf_detect(domain: str) -> str:
    """wafw00f — detect the WAF in front of the site."""
    if not _have("wafw00f"):
        return ""
    raw = _ANSI.sub("", _run(["wafw00f", f"https://{domain}"], 30))
    m = re.search(r"is behind (.+?)(?: WAF| \()", raw)
    if m:
        return m.group(1).strip()
    if "No WAF detected" in raw or "seems to be behind a WAF" in raw:
        return "none detected" if "No WAF" in raw else "generic/unknown"
    return ""


# ─── technology stack (whatweb) ─────────────────────────────────────────────────

def tech_stack(domain: str) -> list[str]:
    if not _have("whatweb"):
        return []
    tmp = tempfile.mktemp(suffix=".json")
    _run(["whatweb", "--no-errors", "-a", "1", f"--log-json={tmp}", f"https://{domain}"], 25)
    tech = []
    try:
        with open(tmp) as f:
            data = json.load(f)
        entries = data if isinstance(data, list) else [data]
        for ent in entries:
            for name, vals in (ent.get("plugins") or {}).items():
                if name in ("Country", "IP", "HTTPServer", "Title", "UncommonHeaders"):
                    continue
                detail = ""
                if isinstance(vals, dict):
                    v = vals.get("version") or vals.get("string") or []
                    detail = ", ".join(v) if isinstance(v, list) else str(v)
                tech.append(f"{name}{' ' + detail if detail else ''}".strip())
    except Exception:
        pass
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass
    return sorted(set(tech))[:30]


# ─── emails / people (theHarvester, best-effort) ────────────────────────────────

def emails(domain: str) -> list[str]:
    if not _have("theHarvester"):
        return []
    prefix = tempfile.mktemp()
    _run(["theHarvester", "-d", domain, "-b", "crtsh,bing,duckduckgo,otx,urlscan",
          "-l", "100", "-f", prefix], 40)
    found = []
    for path in (prefix + ".json", prefix):
        try:
            with open(path) as f:
                d = json.load(f)
            found = d.get("emails", []) or []
            break
        except Exception:
            continue
    try:
        os.remove(prefix + ".json")
    except Exception:
        pass
    return sorted(set(found))[:40]


# ─── Google-dork (inurl:) gathering via DuckDuckGo (keyless) ────────────────────

_INURL_DORKS = [
    ("Admin panels",       "inurl:admin OR inurl:administrator OR inurl:cpanel OR inurl:wp-admin"),
    ("Login portals",      "inurl:login OR inurl:signin OR inurl:auth OR inurl:sso OR inurl:portal"),
    ("Config / env files", "inurl:config OR inurl:.env OR inurl:settings OR inurl:web.config OR ext:ini"),
    ("Backups / archives", "inurl:backup OR ext:bak OR ext:old OR ext:zip OR ext:tar OR ext:gz"),
    ("Databases / SQL",    "inurl:phpmyadmin OR ext:sql OR inurl:db OR inurl:adminer OR inurl:dump"),
    ("API / docs",         "inurl:api OR inurl:swagger OR inurl:graphql OR inurl:wsdl OR inurl:openapi"),
    ("Dir listing",        "intitle:index.of OR inurl:listing"),
    ("Debug / info leak",  "inurl:debug OR inurl:phpinfo OR inurl:test OR inurl:.git OR inurl:trace"),
    ("Documents",          "ext:pdf OR ext:xls OR ext:xlsx OR ext:doc OR ext:csv OR ext:txt"),
    ("Logs / secrets",     "inurl:wp-config OR ext:log OR inurl:credentials OR intext:password"),
    ("Cloud / storage",    "inurl:s3 OR inurl:blob OR inurl:storage OR inurl:bucket"),
    ("Dev / staging",      "inurl:dev OR inurl:staging OR inurl:uat OR inurl:jenkins OR inurl:gitlab"),
    ("Webcams / devices",  "inurl:webcam OR inurl:cgi-bin OR inurl:printer OR inurl:router"),
    ("Error pages",        "intext:\"sql syntax\" OR intext:\"stack trace\" OR intext:\"fatal error\""),
]

_DDG_HTML = "https://html.duckduckgo.com/html/"


def _ddg(query: str, per: int = 6) -> list[tuple]:
    try:
        r = requests.get(_DDG_HTML, params={"q": query}, headers=sources.HEADERS, timeout=12)
    except Exception:
        return []
    pairs = re.findall(r'result__a"\s+href="([^"]+)"[^>]*>(.*?)</a>', r.text, re.S)
    out = []
    for href, text in pairs:
        if "uddg=" in href:
            try:
                href = unquote(parse_qs(urlparse(href).query).get("uddg", [""])[0])
            except Exception:
                continue
        if href.startswith("http"):
            title = re.sub(r"<[^>]+>", "", text).strip()
            out.append((href, title[:90]))
        if len(out) >= per:
            break
    return out


def inurl_dorks(domain: str) -> list[dict]:
    """Run a pack of `site:<domain> inurl:<sensitive>` dorks (DuckDuckGo, keyless)."""
    out, seen = [], set()

    def _one(args):
        label, dork = args
        hits = _ddg(f"site:{domain} {dork}", per=6)
        return label, [(u, t) for (u, t) in hits if domain in u]

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        for label, hits in ex.map(_one, _INURL_DORKS):
            for url, title in hits:
                if url in seen:
                    continue
                seen.add(url)
                out.append({"category": label, "url": url, "title": title or url})
    return out


# ─── username footprint (sherlock) ──────────────────────────────────────────────

def username_footprint(username: str, timeout: int = 60) -> list[dict]:
    if not username or not _have("sherlock"):
        return []
    out_dir = tempfile.mkdtemp()
    txt = os.path.join(out_dir, f"{username}.txt")
    _run(["sherlock", username, "--timeout", "5", "--no-color",
          "--folderoutput", out_dir], timeout)
    hits = []
    try:
        with open(txt) as f:
            for line in f:
                line = line.strip()
                if line.startswith("http"):
                    site = line.split("/")[2] if "//" in line else line
                    hits.append({"site": site, "url": line})
    except Exception:
        pass
    return hits[:60]


# ─── orchestrator ───────────────────────────────────────────────────────────────

def gather(domain: str, username: str = "") -> dict:
    """Run all OSINT collectors in parallel; return a structured dossier."""
    result = {"domain": domain, "tools": {
        "subfinder": _have("subfinder"), "whatweb": _have("whatweb"),
        "theHarvester": _have("theHarvester"), "sherlock": _have("sherlock"),
        "nmap": _have("nmap"), "httpx": _have("httpx"), "wafw00f": _have("wafw00f"),
    }}

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        f_reg = ex.submit(registration, domain)
        f_dns = ex.submit(dns_records, domain)
        f_sub = ex.submit(subdomains, domain)
        f_tech = ex.submit(tech_stack, domain)
        f_mail = ex.submit(emails, domain)
        f_ip = ex.submit(ip_profile, domain)
        f_nmap = ex.submit(nmap_scan, domain)
        f_web = ex.submit(web_fingerprint, domain)
        f_waf = ex.submit(waf_detect, domain)
        f_hdr = ex.submit(http_headers, domain)
        f_dork = ex.submit(inurl_dorks, domain)
        f_user = ex.submit(username_footprint, username) if username else None

        result["registration"] = f_reg.result()
        result["dns"] = f_dns.result()
        subs = f_sub.result()
        result["subdomains"] = subs
        result["tech"] = f_tech.result()
        result["emails"] = f_mail.result()
        result["ip_profile"] = f_ip.result()
        result["nmap"] = f_nmap.result()
        result["web"] = f_web.result()
        result["waf"] = f_waf.result()
        result["http"] = f_hdr.result()
        result["dorks"] = f_dork.result()
        result["infrastructure"] = infrastructure(domain, subs)
        result["username"] = {"query": username, "hits": f_user.result()} if f_user else None

    result["counts"] = {
        "subdomains": len(result["subdomains"]),
        "emails": len(result["emails"]),
        "tech": len(result["tech"]),
        "open_ports": len(result["nmap"]["ports"]),
        "neighbours": len(result["infrastructure"]["reverse_ip"]["neighbours"]),
        "hosts": len(result["infrastructure"]["hosts"]),
    }
    return result


if __name__ == "__main__":
    import sys
    dom = sources.extract_domain(sys.argv[1] if len(sys.argv) > 1 else "example.com")
    print(json.dumps(gather(dom), indent=2))
