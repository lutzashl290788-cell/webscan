"""Tests for report anonymisation."""
from __future__ import annotations

from webscan.anonymize import _scrub, anonymize_report
from webscan.models import Finding, ScanReport, Severity, TargetResult


def test_scrub_private_ips() -> None:
    secrets: list[str] = []
    assert _scrub("connect to 192.168.1.10 and 10.0.0.5", secrets) == (
        "connect to [REDACTED_IP] and [REDACTED_IP]"
    )
    assert _scrub("aws 169.254.169.254", secrets) == "aws [REDACTED_IP]"
    # Public IPs are left intact.
    assert _scrub("8.8.8.8 is public", secrets) == "8.8.8.8 is public"


def test_scrub_home_paths() -> None:
    secrets: list[str] = []
    assert _scrub("/home/alice/secret.txt", secrets) == "/[REDACTED_PATH]/secret.txt"
    assert _scrub(r"C:\Users\bob\file", secrets) == r"[REDACTED_PATH]\file"


def test_scrub_named_secrets() -> None:
    out = _scrub("scan run by my-laptop as operator", ["my-laptop", "operator"])
    assert "my-laptop" not in out
    assert "operator" not in out
    assert out.count("[REDACTED]") == 2


def test_anonymize_report_deep() -> None:
    report = ScanReport(
        total_findings=1,
        targets=[
            TargetResult(
                target="https://example.com",
                findings=[
                    Finding(
                        plugin="ssrf",
                        title="SSRF to 192.168.0.1",
                        severity=Severity.HIGH,
                        description="Server fetched 10.1.2.3 from /home/alice/app",
                        url="https://example.com/?url=http://127.0.0.1",
                        evidence={"path": "/home/alice/loot", "ip": "192.168.0.1"},
                    )
                ],
                errors=["failed at /home/alice/x"],
            )
        ],
    )

    clean = anonymize_report(report)
    f = clean.targets[0].findings[0]

    assert "192.168.0.1" not in f.title
    assert "10.1.2.3" not in f.description
    assert "/home/alice" not in f.description
    assert "127.0.0.1" not in f.url
    assert f.evidence["ip"] == "[REDACTED_IP]"
    assert "[REDACTED_PATH]" in f.evidence["path"]
    assert "/home/alice" not in clean.targets[0].errors[0]

    # Original report is untouched (deep copy).
    assert "192.168.0.1" in report.targets[0].findings[0].title
