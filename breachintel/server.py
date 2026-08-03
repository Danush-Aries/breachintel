#!/usr/bin/env python3
"""
breachintel web GUI server — FastAPI backend.
Serves the UI from ./ui/ and exposes /api/scan.
"""

import os
import sys
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

# make sure local modules resolve
sys.path.insert(0, str(Path(__file__).parent))
import sources
import forums as forums_mod
import takedown as takedown_mod
import sky as sky_mod
import threats as threats_mod
import osint as osint_mod
import advanced as advanced_mod
import ransomwatch as ransom_mod
import recon_plus as reconplus_mod

app = FastAPI(title="BreachIntel")
UI_DIR = Path(__file__).parent / "ui"


class ScanRequest(BaseModel):
    target: str
    include_forums: bool = False


class TakedownRequest(BaseModel):
    target: str
    findings: list = []
    scanned_at: str = ""


class OsintRequest(BaseModel):
    target: str
    username: str = ""


class AdvancedRequest(BaseModel):
    target: str
    hosts: list = []
    asn: str = ""
    lookalikes: list = []


@app.post("/api/scan")
async def scan(req: ScanRequest):
    domain = sources.extract_domain(req.target)
    if not domain or "." not in domain:
        return JSONResponse({"error": f"Cannot parse domain from: {req.target}"}, status_code=400)

    result = sources.run_all(domain)
    forum_findings = []
    if req.include_forums:
        forum_findings = forums_mod.scan_forums(domain)

    all_findings = result["findings"] + forum_findings
    return {
        "domain": domain,
        "scanned_at": result["scanned_at"],
        "findings": all_findings,
        "subdomains": result.get("subdomains", []),
        "target_geo": result.get("target_geo"),
        "risk": sources.compute_risk(all_findings),
        "errors": result.get("errors", []),
        "total": len(all_findings),
    }


@app.post("/api/takedown")
async def takedown(req: TakedownRequest):
    """Enrich exposure hosts with hosting + abuse intel for takedown action."""
    domain = sources.extract_domain(req.target)
    findings = req.findings
    if not findings:
        result = sources.run_all(domain)
        findings = result["findings"]
        scanned_at = result["scanned_at"]
    else:
        scanned_at = req.scanned_at

    records = takedown_mod.enrich_hosts(findings)
    return {
        "domain": domain,
        "records": records,
        "host_count": len(records),
        "abuse_contacts": sorted({r["abuse_email"] for r in records if r["abuse_email"]}),
        "scanned_at": scanned_at,
    }


@app.post("/api/takedown/report")
async def takedown_report(req: TakedownRequest):
    """Return a formatted, send-ready takedown dossier as plaintext."""
    domain = sources.extract_domain(req.target)
    findings = req.findings
    if not findings:
        result = sources.run_all(domain)
        findings = result["findings"]
        scanned_at = result["scanned_at"]
    else:
        scanned_at = req.scanned_at

    records = takedown_mod.enrich_hosts(findings)
    report = takedown_mod.build_report(domain, records, findings, scanned_at)
    return PlainTextResponse(report)


@app.get("/api/sky/aircraft")
def sky_aircraft(lamin: float, lomin: float, lamax: float, lomax: float):
    """Live aircraft (OpenSky) inside the given lat/lon bounding box."""
    return {"aircraft": sky_mod.aircraft(lamin, lomin, lamax, lomax)}


@app.get("/api/sky/satellites")
def sky_satellites(group: str = "stations,visual"):
    """Satellite TLE sets (CelesTrak) — positions propagated client-side."""
    return {"satellites": sky_mod.satellites(group)}


@app.get("/api/sky/cams")
def sky_cams():
    """Curated intentionally-public live webcams (no exposed/private cameras)."""
    return {"cams": sky_mod.public_cams()}


@app.get("/api/geocode")
def geocode(q: str):
    """Forward-geocode a place name → lat/lon (OpenStreetMap, keyless)."""
    return sky_mod.geocode(q)


@app.get("/api/georecon")
def georecon(lat: float, lon: float, radius_m: int = 100):
    """Geo reconnaissance of a radius: public cams + (key-gated) Shodan device metadata."""
    return sky_mod.geo_recon(lat, lon, radius_m)


@app.get("/api/threats")
def threat_feed():
    """Real-time global threat feed (URLhaus malware URLs + Feodo botnet C2)."""
    feed = threats_mod.feed()
    return {"threats": feed, "count": len(feed)}


@app.get("/api/news")
def hacking_news():
    """Latest hacking / breach / threat news across security feeds."""
    items = sources.latest_news()
    return {"news": items, "count": len(items)}


@app.get("/api/forums/status")
def forums_status():
    """Live online/offline/seized status of tracked breach & hacking forums."""
    st = forums_mod.forums_status()
    return {"forums": st, "online": sum(1 for f in st if f["status"] == "online")}


@app.get("/api/ransom/recent")
def ransom_recent():
    """Live recent ransomware victim posts (ransomlook.io)."""
    items = ransom_mod.recent()
    return {"recent": items, "count": len(items)}


@app.get("/api/ransom/groups")
def ransom_groups():
    """Every tracked ransomware group (ransomlook.io)."""
    g = ransom_mod.groups()
    return {"groups": g, "count": len(g)}


@app.get("/api/ransom/markets")
def ransom_markets():
    """Every tracked dark-web market (ransomlook.io)."""
    m = ransom_mod.markets()
    return {"markets": m, "count": len(m)}


@app.post("/api/vulnscan")
async def vuln_scan(req: OsintRequest):
    """nuclei vulnerability scan (exposures / misconfig / CVEs)."""
    domain = sources.extract_domain(req.target)
    return osint_mod.nuclei_scan(domain)


@app.post("/api/advanced")
async def advanced_intel(req: AdvancedRequest):
    """10-module advanced intelligence: Shodan footprint, email grade, ASN threat, typosquat triage."""
    domain = sources.extract_domain(req.target)
    return advanced_mod.gather(domain, req.hosts, req.asn, req.lookalikes)


@app.post("/api/reconplus")
async def recon_plus(req: AdvancedRequest):
    """Advanced recon: subdomain takeover, cloud buckets, Shodan host intel, live crawl."""
    domain = sources.extract_domain(req.target)
    return reconplus_mod.gather(domain, req.hosts, req.hosts)


@app.post("/api/osint")
async def osint_dossier(req: OsintRequest):
    """Deep OSINT + recon dossier: nmap, IP profile, DNS, subdomains, tech, WAF…"""
    domain = sources.extract_domain(req.target)
    if not domain or "." not in domain:
        return JSONResponse({"error": f"Cannot parse domain from: {req.target}"}, status_code=400)
    return osint_mod.gather(domain, req.username or "")


@app.get("/api/health")
def health():
    """Liveness + capability check."""
    try:
        import shodanpool
        keys = len(shodanpool._keys())
    except Exception:
        keys = 0
    return {"status": "ok", "shodan_keys": keys,
            "modules": ["scan", "osint", "advanced", "reconplus", "takedown",
                        "sky", "threats", "ransomwatch"]}


@app.get("/")
def index():
    return FileResponse(UI_DIR / "index.html")


app.mount("/", StaticFiles(directory=UI_DIR), name="ui")


def run(port: int = 7474):
    print(f"\n  BreachIntel GUI → http://localhost:{port}\n")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    run()
