#!/usr/bin/env python3
"""
breachintel.forums — forum + Telegram + Tor + dork monitoring via Playwright.

Features:
  - Multi-mirror fallback: tries each URL in order, uses first live one.
  - Tor support: if tor is running on 9050, .onion mirrors are tried via SOCKS5.
  - Playwright-based scraping (degrades to liveness-only if not installed).
  - Telegram channel scanning.
  - Brave/DDG dork sweep.
"""

import re
import socket
import time
import concurrent.futures
from urllib.parse import quote_plus

import requests

try:
    from bs4 import BeautifulSoup
    _HAVE_BS4 = True
except Exception:
    _HAVE_BS4 = False

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
HEADERS = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}

TOR_PROXY = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}

# ── forum registry ─────────────────────────────────────────────────────────────
# Each entry: mirrors tried in order (clearnet first, .onion last if Tor up).
# search: URL fragment with {q} placeholder.
FORUMS = [
    {
        "name": "BreachForums",
        "mirrors": [
            "https://breachforums.st",
            "https://breachforums.cx",
            "https://breachforums.vc",
            "http://breachforumsiqafp3fmn4i3za6r5vb7ufubzshxrwxhb3xlbqwwmlbgad.onion",
        ],
        "search": "/search.php?action=do_search&keywords={q}&sort_dir=DESC",
        "cat": "breach",
    },
    {
        "name": "LeakBase",
        "mirrors": [
            "https://leakbase.io",
            "https://leakbase.cc",
        ],
        "search": "/search/{q}",
        "cat": "breach",
    },
    {
        "name": "Exposed.vc",
        "mirrors": [
            "https://exposed.vc",
        ],
        "search": "/search?q={q}",
        "cat": "breach",
    },
    {
        "name": "LeakZone",
        "mirrors": [
            "https://leakzone.net",
        ],
        "search": "/search?q={q}",
        "cat": "breach",
    },
    {
        "name": "DataBreaches.net",
        "mirrors": [
            "https://databreaches.net",
        ],
        "search": "/?s={q}",
        "cat": "breach",
    },
    {
        "name": "XSS.is",
        "mirrors": [
            "https://xss.is",
            "http://xssforumv3isucukbxhdhwz67hoa5e2voakcfkuieq4ch257vsburuid.onion",
        ],
        "search": "/search/?q={q}",
        "cat": "hacking",
    },
    {
        "name": "Exploit.in",
        "mirrors": [
            "https://exploit.in",
            "http://exploitinqx4g7m4wefhgwfpxglm3amjqylnzirxjwkwf4k3gvkklxsxad.onion",
        ],
        "search": "/search/?q={q}",
        "cat": "hacking",
    },
    {
        "name": "Nulled.to",
        "mirrors": [
            "https://www.nulled.to",
        ],
        "search": "/index.php?app=core&module=search&do=search&fromSearchBar=1&search_term={q}",
        "cat": "cracking",
    },
    {
        "name": "Cracked.io",
        "mirrors": [
            "https://cracked.io",
            "https://cracked.sh",
        ],
        "search": "/search?q={q}",
        "cat": "cracking",
    },
    {
        "name": "HackForums",
        "mirrors": [
            "https://hackforums.net",
        ],
        "search": "/search.php?action=do_search&keywords={q}",
        "cat": "hacking",
    },
    {
        "name": "RaidForums Archive",
        "mirrors": [
            "https://raidforums.archive.social",
        ],
        "search": "/?s={q}",
        "cat": "breach",
    },
    {
        "name": "Forum.rip",
        "mirrors": [
            "https://forum.rip",
        ],
        "search": "/search?q={q}",
        "cat": "breach",
    },
    {
        "name": "Dread",
        "mirrors": [
            "http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion",
        ],
        "search": "/post/search/?search={q}",
        "cat": "darkweb",
    },
    {
        "name": "KickAss",
        "mirrors": [
            "http://kickassugvgoftuk.onion",
        ],
        "search": "/search.php?action=do_search&keywords={q}",
        "cat": "hacking",
    },
]

TELEGRAM_CHANNELS = [
    "https://t.me/s/breachleaks",
    "https://t.me/s/dataleak",
    "https://t.me/s/databreachleaks",
    "https://t.me/s/BF_Channels",
    "https://t.me/s/leakbase_official",
    "https://t.me/s/cISINTEL",
]

DORKS = [
    'site:pastebin.com "{domain}"',
    'site:github.com "{domain}" credentials OR passwords OR breach',
    '"{domain}" "data breach" OR "database leak"',
    '"{domain}" dump filetype:sql OR filetype:csv',
    'site:raidforums.com "{domain}"',
    'site:breachforums.st "{domain}"',
    '"{domain}" site:ghostbin.co OR site:rentry.co OR site:hastebin.com',
]


# ── Tor check ──────────────────────────────────────────────────────────────────

def _tor_alive() -> bool:
    try:
        s = socket.create_connection(("127.0.0.1", 9050), timeout=2)
        s.close()
        return True
    except Exception:
        return False


_TOR_UP = None  # cached after first check


def tor_up() -> bool:
    global _TOR_UP
    if _TOR_UP is None:
        _TOR_UP = _tor_alive()
    return _TOR_UP


# ── helpers ────────────────────────────────────────────────────────────────────

def _finding(source, category, severity, title, detail="", url=""):
    return {"source": source, "category": category, "severity": severity,
            "title": title, "detail": detail, "country": "", "date": "", "url": url}


def _safe_get(url, timeout=10, use_tor=False):
    proxies = TOR_PROXY if use_tor else {}
    try:
        return requests.get(url, headers=HEADERS, timeout=timeout,
                            allow_redirects=True, proxies=proxies)
    except Exception:
        return None


def _is_onion(url: str) -> bool:
    return ".onion" in url


def _resolve_mirror(forum: dict) -> tuple[str | None, bool]:
    """Return (live_url, is_tor) — tries clearnet first, onion if Tor is up."""
    for url in forum["mirrors"]:
        is_onion = _is_onion(url)
        if is_onion and not tor_up():
            continue
        r = _safe_get(url, timeout=8, use_tor=is_onion)
        if r is None:
            continue
        if "seized" in (r.text or "").lower():
            continue
        if r.status_code in (200, 301, 302, 403):
            return url, is_onion
    return None, False


def check_forum_live(forum: dict) -> tuple[str, str | None, bool]:
    """Return (status, live_url, is_tor)."""
    url, is_tor = _resolve_mirror(forum)
    if url:
        return "online", url, is_tor
    return "offline", None, False


def _clean_title(text: str) -> str:
    text = re.sub(r'^[A-Za-z0-9 .]+[a-z0-9]+\.[a-z]{2,6}›\s*[A-Za-z0-9]+\s*', '', text).strip()
    text = re.sub(r'^[a-z0-9.-]+\.[a-z]{2,6}\s*[›>]\s*', '', text).strip()
    return text


def _search_forum(page, forum: dict, base_url: str, query: str) -> list[dict]:
    if not forum.get("search") or not _HAVE_BS4:
        return []
    out = []
    url = base_url.rstrip("/") + "/" + forum["search"].format(q=quote_plus(query)).lstrip("/")
    try:
        page.goto(url, timeout=20000, wait_until="domcontentloaded")
        page.wait_for_timeout(2000)
        soup = BeautifulSoup(page.content(), "html.parser")
        text = soup.get_text().lower()
        company = query.split(".")[0].lower()
        if text.count(company) < 2:
            return []
        for sel in ["h3 a", ".thread-title a", ".subject a", "a.subject_new",
                    "h2 a", ".post-subject a", ".threadtitle a", ".topic-title a"]:
            for link in soup.select(sel)[:6]:
                t = link.get_text(strip=True)
                href = link.get("href", "")
                if not href.startswith("http"):
                    href = base_url.rstrip("/") + "/" + href.lstrip("/")
                if len(t) > 5 and company in (t + href).lower():
                    out.append(_finding(forum["name"], forum["cat"], "high",
                                        _clean_title(t)[:100] or t[:100],
                                        f"Match on {forum['name']} for '{query}'", href))
            if out:
                break
        if not out and company in text:
            out.append(_finding(forum["name"], forum["cat"], "medium",
                                f"'{query}' mentioned on {forum['name']}",
                                "Unstructured match — check manually", url))
    except Exception:
        pass
    return out


def _search_telegram(page, domain: str) -> list[dict]:
    if not _HAVE_BS4:
        return []
    out = []
    root = domain.split(".")[0].lower()
    for chan in TELEGRAM_CHANNELS:
        try:
            page.goto(chan, timeout=15000, wait_until="domcontentloaded")
            page.wait_for_timeout(1200)
            soup = BeautifulSoup(page.content(), "html.parser")
            for msg in soup.select(".tgme_widget_message_text"):
                txt = msg.get_text()
                if root in txt.lower() or domain in txt.lower():
                    out.append(_finding(f"Telegram/{chan.split('/')[-1]}", "telegram", "high",
                                        f"Mention: {txt[:80]}", txt[:280], chan))
        except Exception:
            pass
    return out


def _search_dorks(page, domain: str) -> list[dict]:
    if not _HAVE_BS4:
        return []
    out, seen = [], set()
    root = domain.split(".")[0].lower()
    for dork in DORKS:
        q = dork.format(domain=domain)
        for engine_url in [
            f"https://search.brave.com/search?q={quote_plus(q)}&source=web",
            f"https://duckduckgo.com/html/?q={quote_plus(q)}",
        ]:
            try:
                page.goto(engine_url, timeout=20000, wait_until="domcontentloaded")
                page.wait_for_timeout(2000)
                soup = BeautifulSoup(page.content(), "html.parser")
                for a in soup.select(".snippet a, h3 a, .title a, .result__title a"):
                    href = a.get("href", "")
                    t = a.get_text(strip=True)
                    if not href.startswith("http") or href in seen:
                        continue
                    if any(x in href for x in ["brave.com", "duckduckgo.com", "google.com"]):
                        continue
                    seen.add(href)
                    if root not in (t + href).lower() and domain not in href.lower():
                        continue
                    if any(x in href for x in ["breachforums", "leakbase", "exposed.vc", "leakzone", "raidforums"]):
                        src, cat, sev = "Breach Forum", "breach", "critical"
                    elif "pastebin" in href or "ghostbin" in href or "rentry" in href:
                        src, cat, sev = "Paste Site", "paste", "high"
                    elif "github" in href:
                        src, cat, sev = "GitHub", "github", "high"
                    else:
                        src, cat, sev = "Search Dork", "google", "medium"
                    out.append(_finding(src, cat, sev,
                                        (_clean_title(t) or href)[:100],
                                        f"Dork: {q[:70]}", href))
                if out:
                    break
            except Exception:
                pass
    return out


# ── main entry ────────────────────────────────────────────────────────────────

def forums_status() -> list[dict]:
    """Live status of every tracked breach/hacking forum (parallel liveness check)."""
    def _check(forum):
        status, url, is_tor = check_forum_live(forum)
        return {
            "name": forum["name"],
            "category": forum.get("cat", ""),
            "status": status,
            "url": url or (forum["mirrors"][0] if forum.get("mirrors") else ""),
            "tor": is_tor,
            "onion_only": all(_is_onion(m) for m in forum.get("mirrors", [])),
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        results = list(ex.map(_check, FORUMS))
    order = {"online": 0, "seized": 1, "offline": 2}
    results.sort(key=lambda r: (order.get(r["status"], 3), r["name"]))
    return results


def scan_forums(domain: str, log_cb=None) -> list[dict]:
    """One-shot forum/Telegram/dork sweep. Degrades gracefully without Playwright."""
    def log(m):
        if log_cb:
            log_cb(m)

    findings = []
    tor_available = tor_up()
    log(f"Tor: {'available (9050)' if tor_available else 'not running — .onion mirrors skipped'}")

    # Liveness check + pick live mirror
    live_forums = []
    for forum in FORUMS:
        status, url, is_tor = check_forum_live(forum)
        via = " (Tor)" if is_tor else ""
        log(f"{forum['name']}: {status}{via}" + (f" → {url}" if url else ""))
        if status == "online" and url:
            live_forums.append((forum, url, is_tor))

    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        log("Playwright not installed — liveness check only")
        log("Install: pip install playwright && playwright install chromium")
        return findings

    try:
        with sync_playwright() as pw:
            launch_args = ["--no-sandbox", "--disable-blink-features=AutomationControlled"]
            if tor_available:
                browser = pw.chromium.launch(
                    headless=True, args=launch_args,
                    proxy={"server": "socks5://127.0.0.1:9050"},
                )
                log("Playwright launched with Tor SOCKS5 proxy")
            else:
                browser = pw.chromium.launch(headless=True, args=launch_args)

            ctx = browser.new_context(
                user_agent=UA,
                extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
            )
            page = ctx.new_page()

            for forum, base_url, is_tor in live_forums:
                label = f"{forum['name']}{' (Tor)' if is_tor else ''}"
                log(f"scraping {label}…")
                hits = _search_forum(page, forum, base_url, domain)
                if hits:
                    log(f"  → {len(hits)} result(s)")
                findings.extend(hits)

            log("scanning Telegram channels…")
            tg = _search_telegram(page, domain)
            if tg:
                log(f"  → {len(tg)} Telegram mention(s)")
            findings.extend(tg)

            log("running search dorks (Brave + DDG)…")
            dork_hits = _search_dorks(page, domain)
            if dork_hits:
                log(f"  → {len(dork_hits)} dork result(s)")
            findings.extend(dork_hits)

            browser.close()
    except Exception as e:
        log(f"Playwright error: {e}")

    return findings


if __name__ == "__main__":
    import json, sys
    d = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(scan_forums(d, log_cb=lambda m: print(" ·", m)), indent=2))
