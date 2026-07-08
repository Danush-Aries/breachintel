"""
breachintel — core unit tests (no network, no API keys required).
"""
import sys
import os
import pytest

# Ensure the package root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sources
import geo


# ─── sources.extract_domain ───────────────────────────────────────────────────

class TestExtractDomain:
    def test_plain_domain(self):
        assert sources.extract_domain("example.com") == "example.com"

    def test_https_url(self):
        assert sources.extract_domain("https://example.com") == "example.com"

    def test_http_url(self):
        assert sources.extract_domain("http://example.com/path?q=1") == "example.com"

    def test_strips_www(self):
        assert sources.extract_domain("www.example.com") == "example.com"

    def test_strips_www_https(self):
        assert sources.extract_domain("https://www.example.com") == "example.com"

    def test_lowercases(self):
        assert sources.extract_domain("EXAMPLE.COM") == "example.com"

    def test_with_port(self):
        assert sources.extract_domain("https://example.com:8080/path") == "example.com"

    def test_subdomain_preserved(self):
        result = sources.extract_domain("https://sub.example.com")
        assert result == "sub.example.com"


# ─── sources._finding ─────────────────────────────────────────────────────────

class TestFinding:
    def test_fields_present(self):
        f = sources._finding("TestSrc", "breach", "high", "Title", "Detail", "US", "2024-01-01", "http://x.com")
        assert f["source"] == "TestSrc"
        assert f["category"] == "breach"
        assert f["severity"] == "high"
        assert f["title"] == "Title"
        assert f["detail"] == "Detail"
        assert f["country"] == "US"
        assert f["date"] == "2024-01-01"
        assert f["url"] == "http://x.com"

    def test_defaults(self):
        f = sources._finding("S", "c", "info", "T")
        assert f["detail"] == ""
        assert f["country"] == ""
        assert f["date"] == ""
        assert f["url"] == ""


# ─── sources.fmt_date ─────────────────────────────────────────────────────────

class TestFmtDate:
    def test_iso_date(self):
        assert sources.fmt_date("2024-06-15") == "2024-06-15"

    def test_iso_datetime(self):
        result = sources.fmt_date("2024-06-15T12:34:56Z")
        assert result == "2024-06-15"

    def test_empty(self):
        assert sources.fmt_date("") == ""

    def test_none_like(self):
        assert sources.fmt_date(None) == ""

    def test_truncates_long(self):
        result = sources.fmt_date("2024-06-15 extra text here")
        assert result.startswith("2024-06-15")


# ─── sources.compute_risk ─────────────────────────────────────────────────────

class TestComputeRisk:
    def test_no_findings(self):
        r = sources.compute_risk([])
        assert r["score"] == 0
        assert r["level"] == "clean"
        assert r["label"] == "No exposure detected"
        assert r["drivers"] == []

    def test_critical_ransomware(self):
        findings = [{"severity": "critical", "category": "ransomware"}]
        r = sources.compute_risk(findings)
        assert r["score"] >= 25
        assert r["level"] in ("medium", "high", "critical")

    def test_multiple_high_breach(self):
        findings = [{"severity": "high", "category": "breach"}] * 5
        r = sources.compute_risk(findings)
        assert r["score"] > 0
        assert "breach record" in " ".join(r["drivers"])

    def test_score_capped_at_100(self):
        findings = [{"severity": "critical", "category": "ransomware"}] * 50
        r = sources.compute_risk(findings)
        assert r["score"] <= 100

    def test_level_progression(self):
        # 1 medium news finding should be low/clean
        findings = [{"severity": "medium", "category": "news"}]
        r = sources.compute_risk(findings)
        assert r["score"] <= 20  # news has very low weight

    def test_result_keys(self):
        r = sources.compute_risk([])
        assert set(r.keys()) >= {"score", "level", "label", "drivers"}


# ─── sources._typo_candidates ─────────────────────────────────────────────────

class TestTypoCandidates:
    def test_returns_set(self):
        cands = sources._typo_candidates("example.com")
        assert isinstance(cands, set)

    def test_not_empty_for_normal_domain(self):
        cands = sources._typo_candidates("example.com")
        assert len(cands) > 0

    def test_original_domain_excluded(self):
        cands = sources._typo_candidates("example.com")
        assert "example.com" not in cands

    def test_tld_swaps_included(self):
        cands = sources._typo_candidates("example.com")
        # should include at least one TLD swap like example.net or example.org
        tld_swaps = {c for c in cands if c.startswith("example.")}
        assert len(tld_swaps) > 0

    def test_short_root_returns_empty(self):
        # root < 3 chars
        cands = sources._typo_candidates("ab.com")
        assert cands == set()


# ─── geo module ───────────────────────────────────────────────────────────────

class TestGeoRenderMap:
    def test_no_findings_returns_text(self):
        from rich.text import Text
        result = geo.render_map([])
        assert isinstance(result, Text)

    def test_with_country_findings(self):
        from rich.text import Text
        findings = [
            {"country": "US", "severity": "critical"},
            {"country": "GB", "severity": "high"},
            {"country": "IN", "severity": "medium"},
        ]
        result = geo.render_map(findings)
        assert isinstance(result, Text)
        plain = result.plain
        assert "GLOBAL THREAT MAP" in plain

    def test_with_target_geo(self):
        from rich.text import Text
        result = geo.render_map([], target_geo={"lat": 37.8, "lon": -122.4,
                                                "country": "US", "country_name": "United States",
                                                "ip": "1.2.3.4", "isp": "TestISP"})
        assert isinstance(result, Text)
        plain = result.plain
        assert "TARGET HOST" in plain

    def test_unknown_country_ignored(self):
        from rich.text import Text
        findings = [{"country": "XX", "severity": "critical"}]
        result = geo.render_map(findings)
        assert isinstance(result, Text)

    def test_missing_country_ignored(self):
        from rich.text import Text
        findings = [{"severity": "high"}]  # no country key
        result = geo.render_map(findings)
        assert isinstance(result, Text)


# ─── geo._cell ────────────────────────────────────────────────────────────────

class TestGeoCell:
    def test_within_bounds(self):
        row, col = geo._cell(0, 0, 20, 60)
        assert 0 <= row < 20
        assert 0 <= col < 60

    def test_north_pole(self):
        row, col = geo._cell(90, 0, 20, 60)
        assert row == 0

    def test_south_pole(self):
        row, col = geo._cell(-90, 0, 20, 60)
        assert row == 19

    def test_date_line_east(self):
        row, col = geo._cell(0, 179, 20, 60)
        # 179 is very close to the right edge; actual value is 58 or 59
        assert col >= 55

    def test_date_line_west(self):
        row, col = geo._cell(0, -180, 20, 60)
        assert col == 0
