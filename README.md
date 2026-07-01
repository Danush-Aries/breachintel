# BreachIntel — Enter a Domain, Get Every Leak, Breach, and Exposure on One Screen

> **18 REST endpoints. 14 OSINT sources. 10-tab investigator GUI with a live global threat map. One `./start.sh`.**

<p align="center"><img src="assets/hero.gif" alt="BreachIntel dashboard — global intel terminal" width="720"></p>

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/Danush-Aries/breachintel/ci.yml?branch=main&style=flat-square" alt="build">
  <img src="https://img.shields.io/badge/license-MIT-00ff41?style=flat-square" alt="license">
  <img src="https://img.shields.io/badge/made%20with-Python-3776AB?style=flat-square&logo=python&logoColor=white" alt="python">
  <img src="https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white" alt="fastapi">
  <img src="https://img.shields.io/badge/Playwright-2EAD33?style=flat-square&logo=playwright&logoColor=white" alt="playwright">
</p>

## Why this exists

Every OSINT tutorial tells you to open 12 tabs — HIBP, DeHashed, Shodan, ransomlook, crt.sh, Sherlock, theHarvester, urlscan, VirusTotal, and so on — and stitch the answers together in your head. BreachIntel is what happens when a bored intern automates that stitching: type a domain, hit Scan, and the FastAPI backend fans out to 14 sources in parallel, computes an exposure score, dedupes the findings, and paints them on a military-style dashboard with a live global threat map. Everything works keyless by default; Shodan keys just unlock the geo/device layers.

## Try it in 60 seconds

```bash
git clone https://github.com/Danush-Aries/breachintel.git
cd breachintel
pip install -r requirements.txt
playwright install chromium         # for forum scraping (optional)

./start.sh                          # → http://localhost:7474
```

CLI still works too:
```bash
python3 breachintel.py example.com                 # rich CLI + ASCII map
python3 breachintel.py example.com --takedown      # hosting + abuse-contact dossier
python3 breachintel.py example.com --tui           # interactive terminal dashboard
python3 breachintel.py example.com --watch         # continuous monitoring
```

## How it works

- **`server.py`** — FastAPI with 18 `/api/*` endpoints; serves the SPA out of `ui/`.
- **10-tab investigator** — Operation (10-phase military recon → dossier), Breach Intel, Website Info, OSINT (WHOIS/subdomains/dorks/Sherlock mindmap), Intel Modules (11 sub-modules: Shodan footprint, ASN threat, typosquat, favicon-hash mmh3 pivot, etc), Recon+ (subdomain takeover, cloud buckets, Katana crawl), Ransomware (ransomlook.io mirror), Live Scrape, News (12 feeds), Radar (live global threat map with URLhaus + Feodo, OpenSky aircraft, CelesTrak satellites, 3D globe).
- **Shodan key pool (`shodanpool.py`)** — rotates keys; even 0-credit keys still power `/host/{ip}` and `/host/count` (both free), which is enough for the geo layers.
- **Playwright-driven forum + Tor scraping (`forums.py`)** — respects a status sidebar (online/offline/seized + `.onion` reachability) so you don't hammer dead sites.
- **Local recon tools auto-detected** — nmap, subfinder, httpx, nuclei, katana, whatweb, wafw00f, theHarvester, sherlock; each surfaces `installed: false` cleanly instead of failing.

## Screenshots

| Operation dashboard | Breach Intel tab | Radar (global threat map) | Ransomware mirror |
|---|---|---|---|
| ![](assets/screenshot-1.png) | ![](assets/screenshot-2.png) | ![](assets/screenshot-3.png) | ![](assets/screenshot-4.png) |

## The web app (left-sidebar navigation)

| Page | What it does |
|------|--------------|
| **Operation** | 10-phase military operation (recon → enumeration → exposure → breach → threat → vuln → HUMINT → dossier) with attack-path & remediation analysis. Default landing — type a domain and Scan runs the whole op. |
| **Breach Intel** | Exposure score + verdict, grouped findings, severity filters with counts, **takedown intelligence** (hosting + verified abuse contacts), JSON export. |
| **Website Info** | Technical recon — IP/ASN profile, nmap ports, web fingerprint, WAF, DNS, HTTP security headers, nuclei vuln scan. |
| **OSINT** | WHOIS, subdomains (subfinder+crt.sh+HackerTarget), harvested emails, reverse-IP neighbours, `inurl:` dorks, Sherlock username footprint, theHarvester-style **interactive mindmap**. |
| **Intel Modules** | 11 modules: Shodan footprint, passive CVE inventory, email scorecard (A–F), ASN bad-neighborhood, typosquat triage, exposure timeline, credential index, attack-surface index, data-class breakdown, monitoring diff, favicon-hash pivot. |
| **Recon+** | Offensive surface — subdomain-takeover detection, cloud bucket discovery (S3/GCS/Azure), full Shodan host intel via the key pool, live endpoint crawl (katana). |
| **Ransomware** | Live ransomlook.io mirror — recent victim posts, 577 groups, 145 markets. |
| **Scrape** | Live monitor — flags every new ransomware publication the moment it lands. |
| **News** | Hacking/breach news (12 feeds) + live forum-status sidebar (online/offline/seized + Tor). |
| **Radar** | Global live map — threats (URLhaus/Feodo), aircraft (OpenSky), satellites (CelesTrak/satellite.js), public cams, satellite imagery (Esri) and 3D globe. Click any spot for geo recon: nearby cameras (OSM + Shodan counts), reverse-geocode, exposed-device counts. |

Top bar: **Report** (download standalone HTML report) · **History** (every past scan, click to reload instantly from cache) · sidebar collapse, light/dark theme.

## Architecture

```
breachintel.py   entry / argparse / mode dispatch
server.py        FastAPI backend — /api/* endpoints, serves ui/
ui/              web app (index.html · styles.css · app.js)

sources.py       free/no-key fan-out + compute_risk()
osint.py         deep recon (RDAP, DNS, subdomains, nmap, httpx, WAF, dorks, sherlock, nuclei)
advanced.py      11 intel modules (Shodan footprint, email grade, ASN threat, typosquat, favicon mmh3 pivot)
recon_plus.py    subdomain takeover, cloud buckets, Shodan host intel, katana crawl
takedown.py      hosting → IP → ASN → RDAP abuse contact + dossier
sky.py           live map: aircraft, satellites, public cams, geocode, OSM cameras, Shodan geo/CCTV
threats.py       real-time threat feed (URLhaus + Feodo, geolocated)
ransomwatch.py   ransomlook.io live mirror (recent / groups / markets)
forums.py        forum + Telegram + Tor (.onion) monitoring (Playwright)
shodanpool.py    Shodan API key pool (rotation, free host/count endpoints)
geo.py report.py tui.py watch.py   CLI map / report / dashboard / monitor
```

## Notes and honest limits

- **No paid keys assumed.** Keyless by default; Shodan optional for geo/device.
- **Camera ethics** — only *intentionally-public* webcams + *crowd-mapped* OSM camera **locations** + Shodan **aggregate counts**. Private/unsecured camera feeds are never accessed.
- **Archive sources** (gau, waybackurls, crt.sh JSON) are flaky in some environments; live tools (katana, subfinder, Shodan) are preferred.
- Results cache in `localStorage` — History reloads instantly.

## Requirements

`pip install -r requirements.txt`, then `playwright install chromium` (optional, for forum scraping). Local recon tools used if present: nmap, subfinder, httpx, nuclei, katana, whatweb, wafw00f, theHarvester, sherlock.

## Stack

FastAPI · httpx · Playwright · Rich (CLI + TUI) · Leaflet + satellite.js (map/globe) · Shodan API · ransomlook.io mirror · URLhaus / Feodo tracker feeds · OpenSky / CelesTrak.

## Contributing

PRs welcome. New sources go in `sources.py` (fan-out) and only need to return a `{finding_type, severity, evidence, url}` dict — the risk scorer, dedupe pass, and UI pick them up automatically.

## License

MIT — see [LICENSE](./LICENSE). **UNCLASSIFIED // FOR AUTHORIZED USE ONLY.**

---

### More from Danush

- [ponytail-for-python](https://github.com/Danush-Aries/ponytail-for-python) — code intelligence for Python codebases
- [Agentic_Systems](https://github.com/Danush-Aries/Agentic_Systems) — reference implementations of agent patterns
- [autonomous-coding-agent](https://github.com/Danush-Aries/autonomous-coding-agent) — full-auto engineering agent
- [computer-use-agent](https://github.com/Danush-Aries/computer-use-agent) — Claude drives your desktop via VNC
- [browser-automation-agent](https://github.com/Danush-Aries/browser-automation-agent) — Claude drives Playwright
- [blinkchat](https://github.com/Danush-Aries/blinkchat) — realtime chat with vibes
