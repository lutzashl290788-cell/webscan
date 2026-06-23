"""Tests for the risk scoring engine and compliance mapping (v2.6.0 killer features)."""
from __future__ import annotations

from webscan.compliance import (
    OWASP_TOP_10_2021,
    compliance_gap_analysis,
    compliance_summary,
    map_findings,
)
from webscan.models import Confidence, Finding, ScanReport, Severity, TargetResult
from webscan.risk import (
    _is_root_url,
    compute_risk_score,
    grade_colour,
    risk_grade,
    risk_recommendation,
    risk_summary,
)

# ─── helpers ────────────────────────────────────────────────────────────────

def _report_with(findings: list[Finding]) -> ScanReport:
    """Build a minimal ScanReport with the given findings on one target."""
    report = ScanReport(scan_started="t0", scan_finished="t1")
    report.targets.append(
        TargetResult(target="https://example.com", findings=findings, scanned_at="t0")
    )
    report.total_findings = len(findings)
    return report


def _finding(
    plugin: str = "headers",
    title: str = "test",
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.FIRM,
    url: str = "https://example.com",
) -> Finding:
    return Finding(
        plugin=plugin,
        title=title,
        severity=severity,
        confidence=confidence,
        description="d",
        url=url,
    )


# ─── risk_grade ─────────────────────────────────────────────────────────────

def test_risk_grade_thresholds() -> None:
    assert risk_grade(100) == "A"
    assert risk_grade(90) == "A"
    assert risk_grade(89.9) == "B"
    assert risk_grade(75) == "B"
    assert risk_grade(55) == "C"
    assert risk_grade(30) == "D"
    assert risk_grade(29.9) == "F"
    assert risk_grade(0) == "F"


def test_grade_colour_returns_hex() -> None:
    assert grade_colour("A").startswith("#")
    assert grade_colour("F") == "#dc2626"
    assert grade_colour("X") == "#8b949e"  # unknown grade → neutral


# ─── _is_root_url ───────────────────────────────────────────────────────────

def test_is_root_url() -> None:
    assert _is_root_url("https://example.com")
    assert _is_root_url("https://example.com/")
    assert _is_root_url("https://example.com/admin")
    assert not _is_root_url("https://example.com/api/v1/users/123")


# ─── compute_risk_score ─────────────────────────────────────────────────────

def test_perfect_score_with_no_findings() -> None:
    """An empty report should score 100/100 (A)."""
    report = _report_with([])
    score, breakdown = compute_risk_score(report)
    assert score == 100.0
    assert breakdown.grade == "A"
    assert breakdown.total_findings == 0
    assert breakdown.total_penalty == 0.0


def test_critical_finding_drops_score_significantly() -> None:
    """A single CRITICAL/FIRM finding should drop the score below 80."""
    report = _report_with([
        _finding(severity=Severity.CRITICAL, confidence=Confidence.FIRM)
    ])
    score, breakdown = compute_risk_score(report)
    assert score < 80
    assert breakdown.grade in ("B", "C", "D", "F")
    assert breakdown.total_penalty > 20


def test_info_finding_barely_moves_score() -> None:
    """An INFO/INFORMATIONAL finding should barely move the score."""
    report = _report_with([
        _finding(severity=Severity.INFO, confidence=Confidence.INFORMATIONAL)
    ])
    score, _ = compute_risk_score(report)
    assert score > 99  # 0.2 * 0.2 * 1.0 * 1.0 = 0.04 penalty


def test_confidence_affects_penalty() -> None:
    """FIRM penalises more than TENTATIVE which penalises more than INFORMATIONAL."""
    firm_report = _report_with([
        _finding(severity=Severity.HIGH, confidence=Confidence.FIRM)
    ])
    tentative_report = _report_with([
        _finding(severity=Severity.HIGH, confidence=Confidence.TENTATIVE)
    ])
    info_report = _report_with([
        _finding(severity=Severity.HIGH, confidence=Confidence.INFORMATIONAL)
    ])
    firm_score, _ = compute_risk_score(firm_report)
    tentative_score, _ = compute_risk_score(tentative_report)
    info_score, _ = compute_risk_score(info_report)
    # Higher confidence → lower score (more penalty).
    assert firm_score < tentative_score < info_score


def test_root_url_penalises_more() -> None:
    """A finding on the root URL should penalise more than on a deep path."""
    root_report = _report_with([
        _finding(url="https://example.com", severity=Severity.HIGH)
    ])
    deep_report = _report_with([
        _finding(url="https://example.com/api/v1/users/123", severity=Severity.HIGH)
    ])
    root_score, _ = compute_risk_score(root_report)
    deep_score, _ = compute_risk_score(deep_report)
    assert root_score < deep_score  # root penalises more → lower score


def test_diminishing_returns() -> None:
    """50 LOW findings should not tank the score to 0 (sub-linear curve)."""
    findings = [
        _finding(severity=Severity.LOW, confidence=Confidence.FIRM, title=f"f{i}")
        for i in range(50)
    ]
    report = _report_with(findings)
    score, breakdown = compute_risk_score(report)
    # With diminishing returns, 50 LOW findings shouldn't push below 30.
    assert score > 30
    assert breakdown.total_findings == 50


def test_score_clamped_to_zero() -> None:
    """Many CRITICAL findings should clamp to 0, not go negative."""
    findings = [
        _finding(severity=Severity.CRITICAL, confidence=Confidence.FIRM, title=f"f{i}")
        for i in range(20)
    ]
    report = _report_with(findings)
    score, _ = compute_risk_score(report)
    assert score == 0.0


def test_breakdown_by_severity() -> None:
    """The breakdown should count findings by severity correctly."""
    report = _report_with([
        _finding(severity=Severity.CRITICAL),
        _finding(severity=Severity.HIGH),
        _finding(severity=Severity.HIGH),
        _finding(severity=Severity.LOW),
    ])
    _, breakdown = compute_risk_score(report)
    assert breakdown.by_severity.get("critical") == 1
    assert breakdown.by_severity.get("high") == 2
    assert breakdown.by_severity.get("low") == 1


def test_breakdown_by_confidence() -> None:
    report = _report_with([
        _finding(confidence=Confidence.FIRM),
        _finding(confidence=Confidence.TENTATIVE),
        _finding(confidence=Confidence.TENTATIVE),
    ])
    _, breakdown = compute_risk_score(report)
    assert breakdown.by_confidence.get("firm") == 1
    assert breakdown.by_confidence.get("tentative") == 2


def test_top_risk_findings_sorted_by_penalty() -> None:
    """The top_risk_findings list should be sorted by penalty (highest first)."""
    report = _report_with([
        _finding(plugin="low_plugin", severity=Severity.LOW),
        _finding(plugin="crit_plugin", severity=Severity.CRITICAL),
        _finding(plugin="med_plugin", severity=Severity.MEDIUM),
    ])
    _, breakdown = compute_risk_score(report)
    assert len(breakdown.top_risk_findings) == 3
    # CRITICAL should be first (highest penalty).
    assert breakdown.top_risk_findings[0][0] == "crit_plugin"


def test_breakdown_to_dict_is_json_serialisable() -> None:
    """to_dict() should return a plain dict that can be JSON-serialised."""
    import json
    report = _report_with([_finding()])
    _, breakdown = compute_risk_score(report)
    d = breakdown.to_dict()
    # Should not raise.
    json.dumps(d)
    assert "score" in d
    assert "grade" in d
    assert "top_risk_findings" in d


# ─── risk_summary + risk_recommendation ─────────────────────────────────────

def test_risk_summary_format() -> None:
    report = _report_with([])
    score, breakdown = compute_risk_score(report)
    summary = risk_summary(score, breakdown)
    assert "100/100" in summary
    assert "(A)" in summary
    assert "0 findings" in summary


def test_risk_recommendation_for_each_grade() -> None:
    for grade in ["A", "B", "C", "D", "F"]:
        rec = risk_recommendation(grade)
        assert len(rec) > 10
        assert rec != "Unknown grade."


def test_risk_recommendation_unknown_grade() -> None:
    assert risk_recommendation("X") == "Unknown grade."


# ─── compliance: map_findings ───────────────────────────────────────────────

def test_map_findings_basic() -> None:
    """SQL injection should map to A03 (Injection)."""
    report = _report_with([
        _finding(plugin="sql_injection", severity=Severity.CRITICAL),
    ])
    mapping = map_findings(report)
    assert "A03" in mapping.by_category
    assert mapping.by_category["A03"][0][0] == "sql_injection"
    assert mapping.total_mapped == 1


def test_map_findings_multiple_categories() -> None:
    """A plugin mapped to multiple OWASP categories should appear in all."""
    report = _report_with([
        _finding(plugin="cookies"),  # maps to A01 + A07
    ])
    mapping = map_findings(report)
    assert "A01" in mapping.by_category
    assert "A07" in mapping.by_category
    assert mapping.total_mapped == 1  # one finding, but in 2 categories


def test_map_findings_unmapped_plugin() -> None:
    """A plugin with no OWASP mapping should go to unmapped."""
    report = _report_with([
        _finding(plugin="nonexistent_plugin"),
    ])
    mapping = map_findings(report)
    assert len(mapping.unmapped) == 1
    assert mapping.unmapped[0][0] == "nonexistent_plugin"
    assert mapping.total_mapped == 0


def test_map_findings_ssrf_maps_to_a10() -> None:
    report = _report_with([_finding(plugin="ssrf")])
    mapping = map_findings(report)
    assert "A10" in mapping.by_category


def test_map_findings_to_dict() -> None:
    import json
    report = _report_with([
        _finding(plugin="xss"),  # A03
        _finding(plugin="headers"),  # A05
    ])
    mapping = map_findings(report)
    d = mapping.to_dict()
    json.dumps(d)
    assert d["total_mapped"] == 2
    assert d["categories_affected"] == 2
    assert d["total_categories"] == 10


# ─── compliance: compliance_summary ─────────────────────────────────────────

def test_compliance_summary_sorted_by_count() -> None:
    """Summary should be sorted by finding count (descending)."""
    report = _report_with([
        _finding(plugin="sql_injection"),  # A03
        _finding(plugin="xss"),            # A03
        _finding(plugin="headers"),        # A05
    ])
    mapping = map_findings(report)
    summary = compliance_summary(mapping)
    assert summary[0][0] == "A03"  # 2 findings → first
    assert summary[0][2] == 2
    assert summary[1][0] == "A05"  # 1 finding → second
    assert summary[1][2] == 1


def test_compliance_summary_includes_severity_breakdown() -> None:
    report = _report_with([
        _finding(plugin="sql_injection", severity=Severity.CRITICAL),
        _finding(plugin="xss", severity=Severity.HIGH),
    ])
    mapping = map_findings(report)
    summary = compliance_summary(mapping)
    # Both map to A03.
    assert summary[0][3] == "1 critical, 1 high"


def test_compliance_summary_empty() -> None:
    """An empty report should produce an empty summary."""
    report = _report_with([])
    mapping = map_findings(report)
    summary = compliance_summary(mapping)
    assert summary == []


# ─── compliance: compliance_gap_analysis ────────────────────────────────────

def test_gap_analysis_shows_clean_categories() -> None:
    """Categories with no findings should appear as gaps."""
    report = _report_with([
        _finding(plugin="sql_injection"),  # only A03
    ])
    mapping = map_findings(report)
    gaps = compliance_gap_analysis(mapping)
    # A03 is affected; all others should be gaps.
    gap_ids = [g[0] for g in gaps]
    assert "A03" not in gap_ids
    assert "A01" in gap_ids
    assert "A05" in gap_ids
    assert len(gaps) == 9  # 10 total - 1 affected


def test_gap_analysis_all_clean() -> None:
    """An empty report should show all 10 categories as gaps."""
    report = _report_with([])
    mapping = map_findings(report)
    gaps = compliance_gap_analysis(mapping)
    assert len(gaps) == 10


def test_owasp_top_10_has_10_categories() -> None:
    assert len(OWASP_TOP_10_2021) == 10
    ids = [c.id for c in OWASP_TOP_10_2021]
    assert ids == ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]


# ─── integration: full report ───────────────────────────────────────────────

def test_full_report_risk_and_compliance() -> None:
    """A realistic report with mixed findings should produce sensible output."""
    report = _report_with([
        _finding(plugin="sql_injection", severity=Severity.CRITICAL, confidence=Confidence.FIRM,
        url="https://example.com/search"),
        _finding(plugin="headers", severity=Severity.HIGH, confidence=Confidence.FIRM,
        url="https://example.com"),
        _finding(plugin="cors", severity=Severity.MEDIUM, confidence=Confidence.FIRM,
        url="https://example.com"),
        _finding(plugin="cookies", severity=Severity.MEDIUM, confidence=Confidence.FIRM,
        url="https://example.com"),
        _finding(plugin="ssl_tls", severity=Severity.LOW, confidence=Confidence.TENTATIVE,
        url="https://example.com"),
        _finding(plugin="tech_fingerprint", severity=Severity.INFO,
         confidence=Confidence.INFORMATIONAL,
        url="https://example.com"),
    ])
    score, breakdown = compute_risk_score(report)
    mapping = map_findings(report)

    # Score should be moderate (has a critical but also some low/info).
    assert 20 < score < 70
    assert breakdown.grade in ("C", "D")

    # Compliance should map to multiple categories.
    assert mapping.total_mapped == 6
    assert len(mapping.by_category) >= 3  # at least A02, A03, A05

    # Summary should be sorted.
    summary = compliance_summary(mapping)
    assert summary[0][2] >= summary[-1][2]
