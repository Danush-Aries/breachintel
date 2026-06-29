<div align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&height=220&color=0:0d1117,30:7e22ce,70:ff006e,100:00ffff&text=BREACHINTEL&fontSize=68&fontColor=ffffff&animation=fadeIn&desc=14-Source+OSINT+%C2%B7+Breach+%C2%B7+Ransomware+%C2%B7+Dark+Web&descAlignY=80&descSize=16" width="100%" alt="BreachIntel"/>
</div>

<div align="center">

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Shodan](https://img.shields.io/badge/Shodan-FC0226?style=for-the-badge&logo=shodan&logoColor=white)
![Playwright](https://img.shields.io/badge/Playwright-2EAD33?style=for-the-badge&logo=playwright&logoColor=white)
![Leaflet](https://img.shields.io/badge/Leaflet-199900?style=for-the-badge&logo=leaflet&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-00ff41?style=for-the-badge)

**18 REST endpoints · 14 OSINT feeds · 10-tab investigator GUI · One FastAPI server.**

</div>

---

# BreachIntel — All-Source Intelligence Terminal

Enter a website → get **every** breach, leak, ransomware listing, infostealer
infection, exposed credential, dark-web mention, vulnerability and hosting
detail for it — on a map-based, military-grade intel dashboard. Free / no-key
sources by default; your Shodan keys unlock the geo/device layers.

```bash
./start.sh                 # → http://localhost:7474
# or:
python3 breachintel.py --gui
```

CLI modes still work too:

```bash
python3 breachintel.py example.com            # Rich CLI report + ASCII map
python3 breachintel.py example.com --takedown # hosting + abuse-contact dossier
python3 breachintel.py example.com --tui      # interactive terminal dashboard
python3 breachintel.py example.com --watch    # continuous monitoring
```

## The web app (left-sidebar navigation)

| Page | What it does |
|------|--------------|
| **⬢ Operation** | 10-phase military operation (recon → enumeration → exposure → breach → threat → vuln → HUMINT → dossier) with attack-path & remediation analysis. Default landing — type a domain and Scan runs the whole op. |
| **🔓 Breach Intel** | Exposure score + verdict, grouped findings, severity filters with counts, **takedown intelligence** (hosting + verified abuse contacts), JSON export. |
| **🌐 Website Info** | Technical recon — IP/ASN profile, nmap ports, web fingerprint, WAF, DNS, HTTP security headers, nuclei vuln scan. |
| **🕵️ OSINT** | WHOIS, subdomains (subfinder+crt.sh+HackerTarget), harvested emails, reverse-IP neighbours, `inurl:` dorks, Sherlock username footprint, theHarvester-style **interactive mindmap**. |
| **⊞ Intel Modules** | 11 modules: Shodan footprint, passive CVE inventory, email scorecard (A–F), ASN bad-neighborhood, typosquat triage, exposure timeline, credential index, attack-surface index, data-class breakdown, monitoring diff, **favicon-hash pivot**. |
| **⚔ Recon+** | Offensive surface — subdomain-takeover detection, cloud bucket discovery (S3/GCS/Azure), full Shodan host intel via the key pool, live endpoint crawl (katana). |
| **☠ Ransomware** | Live ransomlook.io mirror — recent victim posts, 577 groups, 145 markets. |
| **🔴 Scrape** | Live monitor — flags every new ransomware publication the moment it lands. |
| **📰 News** | Hacking/breach news (12 feeds) + live forum-status sidebar (online/offline/seized + Tor). |
| **📡 Radar** | Global live map — threats (URLhaus/Feodo), aircraft (OpenSky), satellites (CelesTrak/satellite.js), public cams, **satellite-imagery view (Esri)** and a **3D globe**. Click any spot for **geo recon**: nearby cameras (OSM + Shodan counts), reverse-geocode, exposed-device counts. |

Top bar: **📄 Report** (download a standalone HTML report) · **🕑 History**
(every past scan, click to reload instantly from cache) · sidebar collapse,
light/dark theme.

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

## Notes & limits (honest)

- **No paid keys assumed.** Everything works keyless except geo/device layers,
  which use the Shodan key pool. Keys with 0 query credits still power
  `/host/{ip}` (full host data) and `/host/count` (geo facets, camera/device
  counts) — both free.
- **Camera ethics:** only *intentionally-public* webcams + *crowd-mapped* OSM
  camera **locations** + Shodan **aggregate counts** are shown. Private /
  unsecured camera **feeds are never accessed**.
- **Archive sources** (gau / waybackurls / crt.sh JSON) are flaky / rate-limited
  in some environments; live tools (katana, subfinder, Shodan) are used instead.
- Results cache in your browser (`localStorage`) — History reloads instantly.

## Requirements

`pip install -r requirements.txt`, then `playwright install chromium` (optional,
for forum scraping). Local recon tools are used if present: nmap, subfinder,
httpx, nuclei, katana, whatweb, wafw00f, theHarvester, sherlock.

UNCLASSIFIED // FOR AUTHORIZED USE ONLY.
