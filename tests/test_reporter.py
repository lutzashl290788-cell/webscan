"""Tests for report generation."""
from __future__ import annotations

import json

from webscan.models import Finding, ScanReport, Severity, TargetResult
from webscan.reporter import Reporter


def _make_report() -> ScanReport:
    return ScanReport(
        scan_started="2025-01-01T00:00:00+00:00",
        scan_finished="2025-01-01T00:00:10+00:00",
        total_findings=1,
        targets=[
            TargetResult(
                target="https://example.com",
                scanned_at="2025-01-01T00:00:05+00:00",
                findings=[
                    Finding(
                        plugin="config_files",
                        title="Exposed file: /.env",
                        severity=Severity.CRITICAL,
                        description="Sensitive file exposed.",
                        url="https://example.com/.env",
                        evidence={"http_status": 200},
                        remediation="Block access.",
                    )
                ],
            )
        ],
    )


def test_json_report_is_valid() -> None:
    reporter = Reporter(_make_report())
    raw = reporter.to_json()
    data = json.loads(raw)
    assert data["total_findings"] == 1
    assert data["targets"][0]["findings"][0]["severity"] == "critical"


def test_markdown_report_contains_target() -> None:
    reporter = Reporter(_make_report())
    md = reporter.to_markdown()
    assert "https://example.com" in md
    assert "CRITICAL" in md
    assert "/.env" in md


def test_html_report_is_self_contained() -> None:
    reporter = Reporter(_make_report())
    html = reporter.to_html()

    assert html.startswith("<!DOCTYPE html>")
    assert "WebScan Security Report" in html
    assert "https://example.com/.env" in html
    # No external assets — fully offline.
    assert "http://" not in html.split("<body>")[1] or "example.com" in html
    assert "<script src" not in html
    assert "cdn" not in html.lower()


def test_html_escapes_malicious_content() -> None:
    report = _make_report()
    report.targets[0].findings[0].title = "<script>alert(1)</script>"
    reporter = Reporter(report)

    html = reporter.to_html()

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
