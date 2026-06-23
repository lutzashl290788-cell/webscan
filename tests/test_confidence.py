"""Tests for the Confidence dimension and false-positive filtering."""
from __future__ import annotations

import csv
import io

from webscan.models import (
    CONFIDENCE_ORDER,
    Confidence,
    Finding,
    ScanReport,
    Severity,
    TargetResult,
)
from webscan.reporter import Reporter, filter_report_by_confidence


def _finding(confidence: Confidence, title: str = "x") -> Finding:
    return Finding(
        plugin="demo",
        title=title,
        severity=Severity.HIGH,
        description="d",
        url="https://example.com",
        confidence=confidence,
    )


def _report(*confidences: Confidence) -> ScanReport:
    findings = [_finding(c, f"finding-{i}") for i, c in enumerate(confidences)]
    report = ScanReport(scan_started="t0", scan_finished="t1")
    report.targets.append(
        TargetResult(
            target="https://example.com",
            findings=findings,
            errors=["boom"],
            scanned_at="t0",
        )
    )
    report.total_findings = len(findings)
    return report


def test_finding_defaults_to_firm() -> None:
    f = Finding(
        plugin="p", title="t", severity=Severity.LOW, description="d", url="u"
    )
    assert f.confidence == Confidence.FIRM


def test_confidence_ordering() -> None:
    assert CONFIDENCE_ORDER[Confidence.FIRM] < CONFIDENCE_ORDER[Confidence.TENTATIVE]
    assert (
        CONFIDENCE_ORDER[Confidence.TENTATIVE]
        < CONFIDENCE_ORDER[Confidence.INFORMATIONAL]
    )


def test_filter_firm_keeps_only_firm() -> None:
    report = _report(
        Confidence.FIRM, Confidence.TENTATIVE, Confidence.INFORMATIONAL
    )
    out = filter_report_by_confidence(report, Confidence.FIRM)
    assert out.total_findings == 1
    assert out.targets[0].findings[0].confidence == Confidence.FIRM
    # Errors and structure are preserved.
    assert out.targets[0].errors == ["boom"]
    assert out.scan_started == "t0"


def test_filter_tentative_keeps_firm_and_tentative() -> None:
    report = _report(
        Confidence.FIRM, Confidence.TENTATIVE, Confidence.INFORMATIONAL
    )
    out = filter_report_by_confidence(report, Confidence.TENTATIVE)
    assert out.total_findings == 2
    kept = {f.confidence for f in out.targets[0].findings}
    assert kept == {Confidence.FIRM, Confidence.TENTATIVE}


def test_filter_informational_keeps_all() -> None:
    report = _report(
        Confidence.FIRM, Confidence.TENTATIVE, Confidence.INFORMATIONAL
    )
    out = filter_report_by_confidence(report, Confidence.INFORMATIONAL)
    assert out.total_findings == 3


def test_filter_does_not_mutate_original() -> None:
    report = _report(Confidence.FIRM, Confidence.INFORMATIONAL)
    filter_report_by_confidence(report, Confidence.FIRM)
    assert report.total_findings == 2  # original untouched


def test_console_summary_tags_non_firm() -> None:
    report = _report(Confidence.FIRM, Confidence.TENTATIVE)
    out = Reporter(report).to_console_summary()
    assert "finding-0" in out
    assert "(~tentative)" in out  # the tentative one is tagged
    # The firm finding carries no tag.
    firm_line = next(line for line in out.splitlines() if "finding-0" in line)
    assert "~" not in firm_line


def test_csv_and_jsonl_carry_confidence() -> None:
    report = _report(Confidence.TENTATIVE)
    reporter = Reporter(report)

    rows = list(csv.reader(io.StringIO(reporter.to_csv())))
    assert rows[0][3] == "confidence"
    assert rows[1][3] == "tentative"

    jsonl = reporter.to_jsonl().strip()
    assert '"confidence": "tentative"' in jsonl


def test_json_report_includes_confidence() -> None:
    report = _report(Confidence.INFORMATIONAL)
    out = Reporter(report).to_json()
    assert '"confidence": "informational"' in out
