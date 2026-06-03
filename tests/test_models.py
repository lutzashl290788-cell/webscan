"""Tests for data models."""
from __future__ import annotations

import json
from dataclasses import asdict

from webscan.models import Finding, Severity, ScanReport, TargetResult


def test_finding_severity_serialises_as_string() -> None:
    f = Finding(
        plugin="test",
        title="Test finding",
        severity=Severity.CRITICAL,
        description="desc",
        url="https://example.com",
    )
    d = asdict(f)
    # Severity(str, Enum) serialises cleanly to JSON
    assert json.dumps(d)  # must not raise
    assert d["severity"] == "critical"


def test_scan_report_total_findings() -> None:
    report = ScanReport(
        scan_started="2025-01-01T00:00:00+00:00",
        scan_finished="2025-01-01T00:00:10+00:00",
        total_findings=2,
        targets=[
            TargetResult(
                target="https://example.com",
                findings=[
                    Finding("p", "t1", Severity.HIGH, "d", "u"),
                    Finding("p", "t2", Severity.LOW, "d", "u"),
                ],
            )
        ],
    )
    assert report.total_findings == 2
