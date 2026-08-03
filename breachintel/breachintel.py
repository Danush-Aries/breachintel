#!/usr/bin/env python3
"""
breachintel — map-based breach & ransomware intelligence terminal.

Enter a website URL → find all breach / leak / ransomware exposure across free,
no-key sources (ransomware.live, ransomlook.io, HIBP catalog, LeakCheck, OTX,
GitHub, crt.sh) plus optional forum/Telegram/dork monitoring, rendered on an
ASCII global threat map.

Modes:
    breachintel.py <url>            Rich CLI report + global threat map (default)
    breachintel.py <url> --tui      Interactive intel-terminal dashboard
    breachintel.py <url> --watch     Continuous forum/ransomware monitoring
    breachintel.py --gui            Launch web GUI at http://localhost:7474
"""

import sys
import json
import argparse

import sources


def main():
    p = argparse.ArgumentParser(
        prog="breachintel",
        description="Map-based breach & ransomware intelligence (free sources, no API keys).",
    )
    p.add_argument("target", nargs="?", help="Domain or URL to investigate (e.g. example.com)")
    p.add_argument("--gui", action="store_true", help="Launch web GUI at http://localhost:7474")
    p.add_argument("--port", type=int, default=7474, metavar="PORT", help="Web GUI port (default 7474)")
    p.add_argument("--tui", action="store_true", help="Launch interactive intel-terminal dashboard")
    p.add_argument("--watch", action="store_true", help="Continuous forum/ransomware monitoring")
    p.add_argument("--interval", type=int, default=300, metavar="SEC", help="Watch poll interval (default 300)")
    p.add_argument("--no-forums", action="store_true", help="Skip Playwright forum/Telegram/dork sweep")
    p.add_argument("--map-only", action="store_true", help="Print only the global threat map")
    p.add_argument("--takedown", action="store_true",
                   help="Trace hosting + abuse contacts and print a takedown dossier")
    p.add_argument("-o", "--output", metavar="FILE", help="Save structured results to JSON")
    args = p.parse_args()

    if args.gui:
        import server
        server.run(port=args.port)
        return

    if not args.target:
        p.print_help()
        sys.exit(0)

    domain = sources.extract_domain(args.target)
    if not domain or "." not in domain:
        print(f"Could not parse a domain from: {args.target}", file=sys.stderr)
        sys.exit(1)

    include_forums = not args.no_forums

    if args.tui:
        import tui
        tui.launch(domain, include_forums=include_forums)
        return

    if args.watch:
        import watch
        watch.run(domain, interval=args.interval, include_forums=include_forums)
        return

    # default: Rich CLI report
    import report
    from rich.console import Console
    console = Console()

    with console.status(f"[green]Scanning free sources for {domain}…", spinner="dots"):
        result = sources.run_all(domain)

    forum_findings = []
    if include_forums:
        import forums
        with console.status("[green]Sweeping forums / Telegram / dorks…", spinner="dots"):
            forum_findings = forums.scan_forums(domain)

    if args.map_only:
        import geo
        console.print(geo.render_map(result["findings"] + forum_findings,
                                     target_geo=result.get("target_geo")))
    elif args.takedown:
        import takedown
        all_findings = result["findings"] + forum_findings
        with console.status("[green]Tracing hosting infrastructure + abuse contacts…", spinner="dots"):
            records = takedown.enrich_hosts(all_findings)
        dossier = takedown.build_report(domain, records, all_findings, result["scanned_at"])
        print(dossier)
    else:
        report.render(result, forum_findings)

    if args.output:
        payload = dict(result)
        payload["forum_findings"] = forum_findings
        with open(args.output, "w") as f:
            json.dump(payload, f, indent=2, default=str)
        console.print(f"\n[green]Saved:[/green] {args.output}")


if __name__ == "__main__":
    main()
