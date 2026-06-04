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
