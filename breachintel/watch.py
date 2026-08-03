#!/usr/bin/env python3
"""
breachintel.watch — continuous forum + ransomware-feed monitoring.

Re-polls ransomware.live, ransomlook.io and forums on an interval; alerts on
NEW hits only (deduped via a persisted seen-set). Best-effort desktop
notification via notify-send + terminal bell.
"""

import os
import json
import time
import shutil
import subprocess
from datetime import datetime

from rich.console import Console

import os
import sources
import forums

console = Console()
CACHE_DIR = os.path.expanduser("~/.breachintel")


def _cache_path(domain: str) -> str:
    os.makedirs(CACHE_DIR, exist_ok=True)
    safe = domain.replace("/", "_")
    return os.path.join(CACHE_DIR, f"{safe}.json")


def _load_seen(domain: str) -> set:
    try:
        with open(_cache_path(domain)) as f:
            return set(json.load(f).get("seen", []))
    except Exception:
        return set()


def _save_seen(domain: str, seen: set):
    try:
        with open(_cache_path(domain), "w") as f:
            json.dump({"seen": sorted(seen), "updated": datetime.now().isoformat()}, f)
    except Exception:
        pass


def _key(f: dict) -> str:
    return f"{f.get('source')}|{f.get('title')}"


def _notify(title: str, body: str):
    if shutil.which("notify-send"):
        try:
            subprocess.run(["notify-send", "-u", "critical", title, body], timeout=5)
        except Exception:
            pass
    print("\a", end="", flush=True)  # terminal bell


def run(domain: str, interval: int = 300, include_forums: bool = True):
    console.print(f"[bold green]BREACHINTEL WATCH[/bold green]  target=[white]{domain}[/white]  "
                  f"interval=[cyan]{interval}s[/cyan]  forums=[cyan]{include_forums}[/cyan]")
    console.print("[dim]Polling free ransomware/forum sources. Ctrl-C to stop.[/dim]\n")

    seen = _load_seen(domain)
    first_cycle = not seen
    cycle = 0
    try:
        while True:
            cycle += 1
            ts = datetime.now().strftime("%H:%M:%S")
            new_hits = []

            for label, fn in (("Ransomware.live", sources.ransomware_live),
                              ("RansomLook", sources.ransomlook)):
                try:
                    for f in fn(domain):
                        if _key(f) not in seen:
                            seen.add(_key(f))
                            new_hits.append(f)
                except Exception as e:  # noqa: BLE001
                    console.print(f"  [dim]{label} error: {e}[/dim]")

            if include_forums:
                try:
                    for f in forums.scan_forums(domain):
                        if _key(f) not in seen:
                            seen.add(_key(f))
                            new_hits.append(f)
                except Exception as e:  # noqa: BLE001
                    console.print(f"  [dim]forums error: {e}[/dim]")

            _save_seen(domain, seen)

            if first_cycle:
                console.print(f"[dim][{ts}] cycle {cycle}: baseline established "
                              f"({len(seen)} known item(s)).[/dim]")
                first_cycle = False
            elif new_hits:
                console.print(f"[bold bright_red][{ts}] ⚠ {len(new_hits)} NEW exposure(s) for {domain}![/bold bright_red]")
                for f in new_hits:
                    console.print(f"   [red]●[/red] [{f['severity'].upper()}] "
                                  f"{f['source']}: {f['title']}  [blue]{f.get('url','')}[/blue]")
                _notify(f"BreachIntel: {len(new_hits)} new hit(s) for {domain}",
                        "; ".join(h["title"][:60] for h in new_hits[:3]))
            else:
                console.print(f"[dim][{ts}] cycle {cycle}: no new exposure ({len(seen)} known).[/dim]")

            time.sleep(interval)
    except KeyboardInterrupt:
        console.print(f"\n[bold green]Watch stopped.[/bold green] {cycle} cycle(s), "
                      f"{len(seen)} total item(s) tracked. Cache: {_cache_path(domain)}")
