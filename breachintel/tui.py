#!/usr/bin/env python3
"""
breachintel.tui — interactive intel-terminal dashboard (Textual).

Tabs: Findings · Map · Forums · Subdomains · Log. Background scan runs the same
free/no-key source layer plus optional forum sweep.
"""

from textual import work
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Input, DataTable, Static, Log, TabbedContent, TabPane
from textual.containers import Container

import sources
import forums
import geo


class BreachIntelApp(App):
    CSS = """
    Screen { background: #04120a; }
    Header { background: #0a2b16; color: #5cff9d; }
    Footer { background: #0a2b16; color: #5cff9d; }
    #target { border: round #2ecc71; background: #04120a; color: #aaffcc; }
    TabbedContent { background: #04120a; }
    DataTable { background: #04120a; color: #cfe; }
    .map { color: #7CFC9A; background: #020a05; padding: 1; }
    Log { background: #020a05; color: #8fbf9f; }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "rescan", "Rescan"),
    ]

    def __init__(self, domain: str, include_forums: bool = True):
        super().__init__()
        self.domain = sources.extract_domain(domain)
        self.include_forums = include_forums
        self.findings: list[dict] = []
        self.target_geo = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Input(value=self.domain, id="target", placeholder="domain or URL…")
        with TabbedContent(initial="findings"):
            with TabPane("Findings", id="findings"):
                yield DataTable(id="findings_table")
            with TabPane("Map", id="map"):
                yield Static("Scanning…", classes="map", id="map_view")
            with TabPane("Forums", id="forums"):
                yield DataTable(id="forums_table")
            with TabPane("Subdomains", id="subs"):
                yield DataTable(id="subs_table")
            with TabPane("Log", id="log"):
                yield Log(id="logbox", highlight=True)
        yield Footer()

    def on_mount(self):
        ft = self.query_one("#findings_table", DataTable)
        ft.add_columns("SEV", "Source", "Finding", "Date")
        fo = self.query_one("#forums_table", DataTable)
        fo.add_columns("SEV", "Source", "Title", "URL")
        st = self.query_one("#subs_table", DataTable)
        st.add_columns("#", "Subdomain")
        self.title = f"BREACHINTEL // {self.domain}"
        self.sub_title = "SIGINT TERMINAL"
        self.run_scan()

    def _log(self, msg: str):
        try:
            self.query_one("#logbox", Log).write_line(msg)
        except Exception:
            pass

    def action_rescan(self):
        self.domain = sources.extract_domain(self.query_one("#target", Input).value)
        self.title = f"BREACHINTEL // {self.domain}"
        self.run_scan()

    def on_input_submitted(self, event: Input.Submitted):
        self.action_rescan()

    @work(thread=True, exclusive=True)
    def run_scan(self):
        domain = self.domain
        self.call_from_thread(self._log, f"[scan] starting {domain}")
        result = sources.run_all(domain, progress_cb=lambda s: self.call_from_thread(self._log, f"[src] {s} done"))
        findings = list(result["findings"])

        forum_findings = []
        if self.include_forums:
            self.call_from_thread(self._log, "[forums] sweeping (Playwright)…")
            forum_findings = forums.scan_forums(domain, log_cb=lambda m: self.call_from_thread(self._log, f"[forum] {m}"))

        all_findings = findings + forum_findings
        self.findings = all_findings
        self.target_geo = result.get("target_geo")
        self.call_from_thread(self._render, result, forum_findings)

    def _render(self, result, forum_findings):
        ft = self.query_one("#findings_table", DataTable)
        ft.clear()
        for f in result["findings"]:
            ft.add_row(f["severity"].upper(), f["source"], f["title"][:70], f.get("date", ""))

        fo = self.query_one("#forums_table", DataTable)
        fo.clear()
        for f in forum_findings:
            fo.add_row(f["severity"].upper(), f["source"], f["title"][:60], f.get("url", "")[:50])

        st = self.query_one("#subs_table", DataTable)
        st.clear()
        for i, s in enumerate(result.get("subdomains", []), 1):
            st.add_row(str(i), s)

        self.query_one("#map_view", Static).update(geo.render_map(self.findings, target_geo=self.target_geo))
        self._log(f"[done] {len(self.findings)} finding(s)")


def launch(domain: str, include_forums: bool = True):
    BreachIntelApp(domain, include_forums=include_forums).run()
