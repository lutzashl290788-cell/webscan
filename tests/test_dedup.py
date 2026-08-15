"""Tests for cross-plugin finding deduplication (webscan.engine)."""
from __future__ import annotations

from webscan.engine import _deduplicate_report_site_findings, deduplicate_findings
from webscan.models import Confidence, Finding, ScanReport, Severity, TargetResult

URL = "https://example.com"


def _finding(
    plugin: str,
    title: str,
    severity: Severity = Severity.MEDIUM,
    *,
    url: str = URL,
    dedup_key: str | None = None,
    confidence: Confidence = Confidence.FIRM,
) -> Finding:
    return Finding(
        plugin=plugin,
        title=title,
        severity=severity,
        description="",
        url=url,
        dedup_key=dedup_key,
        confidence=confidence,
    )


def test_findings_without_key_are_never_merged() -> None:
    """A None dedup_key means "no other plugin reports this" — keep them all."""
    findings = [
        _finding("headers", "A"),
        _finding("cookies", "B"),
        _finding("cors", "C"),
    ]
    assert len(deduplicate_findings(findings)) == 3


def test_same_issue_from_two_plugins_collapses_to_most_severe() -> None:
    """The real HSTS case: headers says HIGH, ssl_tls says MEDIUM."""
    out = deduplicate_findings([
        _finding(
            "headers", "Missing header: Strict-Transport-Security",
            Severity.HIGH, dedup_key="missing-header:strict-transport-security",
        ),
        _finding(
            "ssl_tls", "Missing HSTS header",
            Severity.MEDIUM, dedup_key="missing-header:strict-transport-security",
        ),
    ])
    assert len(out) == 1
    assert out[0].severity is Severity.HIGH
    assert out[0].plugin == "headers"


def test_merged_plugins_are_recorded_not_lost() -> None:
    out = deduplicate_findings([
        _finding("headers", "high one", Severity.HIGH, dedup_key="k"),
        _finding("ssl_tls", "low one", Severity.LOW, dedup_key="k"),
    ])
    assert out[0].evidence["also_reported_by"] == ["ssl_tls"]


def test_same_key_on_different_urls_stays_separate() -> None:
    """Dedup is per-URL — the same issue on two pages is two findings."""
    out = deduplicate_findings([
        _finding("headers", "x", dedup_key="k", url="https://a.example"),
        _finding("headers", "x", dedup_key="k", url="https://b.example"),
    ])
    assert len(out) == 2


def test_site_key_collapses_across_paths_but_not_hosts() -> None:
    out = deduplicate_findings([
        _finding("dns_security", "Missing SPF", dedup_key="site:dns:spf",
                 url="https://example.com/"),
        _finding("dns_security", "Missing SPF", dedup_key="site:dns:spf",
                 url="https://example.com/login"),
        _finding("dns_security", "Missing SPF", dedup_key="site:dns:spf",
                 url="https://other.example/"),
    ])
    assert len(out) == 2


def test_report_level_site_key_collapses_crawled_results() -> None:
    first = _finding("headers", "No framing", dedup_key="site:framing-protection-missing")
    second = _finding(
        "headers", "No framing", dedup_key="site:framing-protection-missing",
        url="https://example.com/account",
    )
    report = ScanReport(targets=[
        TargetResult(target=URL, findings=[first]),
        TargetResult(target="https://example.com/account", findings=[second]),
    ])
    _deduplicate_report_site_findings(report)
    assert sum(len(target.findings) for target in report.targets) == 1


def test_confidence_breaks_severity_ties() -> None:
    out = deduplicate_findings([
        _finding("aaa", "tentative", dedup_key="k", confidence=Confidence.TENTATIVE),
        _finding("zzz", "firm", dedup_key="k", confidence=Confidence.FIRM),
    ])
    assert len(out) == 1
    assert out[0].plugin == "zzz"  # firm beats tentative despite later plugin name


def test_result_is_independent_of_plugin_ordering() -> None:
    """Plugins run concurrently, so the winner must not depend on arrival order."""
    a = _finding("clickjacking", "framable", dedup_key="framing-protection-missing")
    b = _finding("headers", "Missing header: X-Frame-Options",
                 dedup_key="framing-protection-missing")
    forward = deduplicate_findings([a, b])
    backward = deduplicate_findings([b, a])
    assert forward[0].plugin == backward[0].plugin == "clickjacking"


def test_first_appearance_order_is_preserved() -> None:
    out = deduplicate_findings([
        _finding("p1", "first"),
        _finding("headers", "dup", Severity.LOW, dedup_key="k"),
        _finding("p2", "third"),
        _finding("ssl_tls", "dup", Severity.HIGH, dedup_key="k"),
    ])
    assert [f.title for f in out] == ["first", "dup", "third"]


def test_empty_input() -> None:
    assert deduplicate_findings([]) == []
