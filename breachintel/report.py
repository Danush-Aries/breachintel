#!/usr/bin/env python3
"""
breachintel.report — Rich CLI report rendering (intel-terminal theme).
Ends with the ASCII global threat map.
"""

from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich import box

import geo

console = Console()

SEV_COLOR = {"critical": "bright_red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
CAT_TITLE = {
    "ransomware": "RANSOMWARE LEAK SITES",
    "breach": "BREACH / CREDENTIAL DATABASES",
    "github": "PUBLIC CODE / REPOS",
    "threat": "THREAT INTELLIGENCE",
    "paste": "PASTE SITES",
    "google": "SEARCH / DORK HITS",
    "telegram": "TELEGRAM CHANNELS",
    "hacking": "HACKING FORUMS",
    "cracking": "CRACKING FORUMS",
}
CAT_ORDER = ["ransomware", "breach", "github", "paste", "telegram", "hacking", "cracking", "google", "threat"]


def banner(domain: str):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    console.print(Panel.fit(
        Text.assemble(
            ("BREACHINTEL ", "bold bright_green"),
            ("// ", "dim green"),
            ("SIGINT TERMINAL", "bold green"),
            ("\nTARGET: ", "dim"), (domain, "bold white"),
            ("   TIMESTAMP: ", "dim"), (now, "white"),
        ),
        border_style="green", box=box.DOUBLE,
        subtitle="[dim]free-source breach & ransomware intelligence[/dim]",
    ))


def _sev_badge(sev: str) -> str:
    c = SEV_COLOR.get(sev, "white")
    return f"[{c}]{sev.upper()}[/{c}]"


def render(result: dict, forum_findings: list[dict] | None = None):
    domain = result["domain"]
    findings = list(result.get("findings", []))
    if forum_findings:
        findings += forum_findings
    subs = result.get("subdomains", [])

    banner(domain)

    # group by category
    by_cat: dict[str, list[dict]] = {}
    for f in findings:
        by_cat.setdefault(f.get("category", "other"), []).append(f)

    for cat in CAT_ORDER:
        items = by_cat.get(cat)
        if not items:
            continue
        style = "red" if cat == "ransomware" else "green"
        console.print(Rule(f"[bold]{CAT_TITLE.get(cat, cat.upper())}[/bold]", style=style))
        t = Table(box=box.SIMPLE_HEAD, header_style="bold green", expand=True, show_edge=False)
        t.add_column("SEV", width=9)
        t.add_column("Source", style="cyan", no_wrap=True)
        t.add_column("Finding", style="white")
        t.add_column("Date", style="dim", width=11)
        for f in items:
            t.add_row(_sev_badge(f.get("severity", "info")), f.get("source", "?"),
                      f.get("title", "")[:90], f.get("date", ""))
        console.print(t)
        console.print()

    if not findings:
        console.print("[bold green]  No breach, ransomware, or forum exposure found across free sources.[/bold green]\n")

    # subdomains (compact)
    if subs:
        console.print(Rule("[bold]ATTACK SURFACE — crt.sh subdomains[/bold]", style="green"))
        console.print(f"  [cyan]{len(subs)} subdomains[/cyan]  [dim]" +
                      "  ".join(subs[:30]) + ("  …" if len(subs) > 30 else "") + "[/dim]\n")

    # global threat map
    console.print(Rule("[bold]GLOBAL THREAT MAP[/bold]", style="green"))
    console.print(geo.render_map(findings, target_geo=result.get("target_geo")))

    # summary
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    console.print(Rule("[bold]SUMMARY[/bold]", style="bold green"))
    s = Table(box=box.SIMPLE, show_header=False)
    s.add_column("k", style="bold")
    s.add_column("v", justify="right")
    s.add_row("Total findings", f"[{'red' if findings else 'green'}]{len(findings)}[/]")
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev_counts.get(sev):
            s.add_row(sev.capitalize(), f"[{SEV_COLOR[sev]}]{sev_counts[sev]}[/]")
    ransom = len(by_cat.get("ransomware", []))
    s.add_row("Ransomware hits", f"[{'bold bright_red' if ransom else 'green'}]{ransom}[/]")
    s.add_row("Subdomains", f"[cyan]{len(subs)}[/cyan]")
    console.print(s)
    if result.get("errors"):
        console.print(f"\n[dim]Sources with errors: {', '.join(result['errors'][:6])}[/dim]")
    console.print("\n[dim green]── UNCLASSIFIED // FOR AUTHORIZED USE ONLY ──[/dim green]")
