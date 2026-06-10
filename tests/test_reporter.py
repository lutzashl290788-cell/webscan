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


def test_console_summary_min_severity_filters() -> None:
    report = _make_report()
    report.targets[0].findings.append(
        Finding(
            plugin="headers",
            title="Missing header",
            severity=Severity.LOW,
            description="x",
            url="https://example.com",
        )
    )
    reporter = Reporter(report)

    out = reporter.to_console_summary(min_severity=Severity.HIGH)

    assert "Exposed file: /.env" in out  # critical passes
    assert "Missing header" not in out   # low filtered out


def test_console_summary_color_adds_ansi() -> None:
    reporter = Reporter(_make_report())

    colored = reporter.to_console_summary(color=True)
    plain = reporter.to_console_summary(color=False)

    assert "\033[" in colored
    assert "\033[" not in plain


def test_sarif_report_structure() -> None:
    reporter = Reporter(_make_report())
    sarif = json.loads(reporter.to_sarif())

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "WebScan"

    # The single critical finding maps to a SARIF error result.
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "config_files"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "https://example.com/.env"
    )

    # The rule is registered once in the driver.
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert rule_ids == ["config_files"]


def test_sarif_dedupes_rules() -> None:
    report = _make_report()
    report.targets[0].findings.append(
        Finding(
            plugin="config_files",
            title="Exposed file: /.git/config",
            severity=Severity.HIGH,
            description="x",
            url="https://example.com/.git/config",
        )
    )
    reporter = Reporter(report)
    sarif = json.loads(reporter.to_sarif())
    run = sarif["runs"][0]

    assert len(run["results"]) == 2
    # Same plugin → one rule entry only.
    assert len(run["tool"]["driver"]["rules"]) == 1


def test_csv_report_has_header_and_rows() -> None:
    import csv
    import io

    reporter = Reporter(_make_report())
    out = reporter.to_csv()

    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0] == [
        "target", "plugin", "severity", "title", "url",
        "description", "remediation", "evidence",
    ]
    assert len(rows) == 2  # header + one finding
    assert rows[1][1] == "config_files"
    assert rows[1][2] == "critical"
    assert rows[1][4] == "https://example.com/.env"


def test_csv_escapes_commas_in_fields() -> None:
    import csv
    import io

    report = _make_report()
    report.targets[0].findings[0].description = "a, b, c with commas"
    reporter = Reporter(report)

    rows = list(csv.reader(io.StringIO(reporter.to_csv())))
    assert rows[1][5] == "a, b, c with commas"
