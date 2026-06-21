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


# ----------------------------------------------------------------------
# Coverage gaps
# ----------------------------------------------------------------------


def test_scrub_empty_text_unchanged() -> None:
    """Empty string should pass through unchanged (early return)."""
    assert _scrub("", []) == ""


def test_scrub_list_and_tuple_recursion() -> None:
    """Lines 70-72: _scrub_value recurses into lists."""
    from webscan.anonymize import _scrub_value
    result = _scrub_value(
        ["hello 192.168.1.1", ["nested", "10.0.0.1"]],
        [],
    )
    assert result[0] == "hello [REDACTED_IP]"
    assert result[1][0] == "nested"
    assert result[1][1] == "[REDACTED_IP]"


def test_scrub_non_scrubable_types_unchanged() -> None:
    """Ints, bools, None pass through _scrub_value untouched."""
    from webscan.anonymize import _scrub_value
    assert _scrub_value(42, []) == 42
    assert _scrub_value(True, []) is True
    assert _scrub_value(None, []) is None


def test_dynamic_secrets_hostname_error_handled() -> None:
    """Lines 43-44: socket.gethostname raising OSError is caught."""
    import socket

    from webscan.anonymize import _dynamic_secrets

    orig = socket.gethostname
    socket.gethostname = lambda: (_ for _ in ()).throw(OSError("no hostname"))
    try:
        # Should not raise; returns list without the hostname entry.
        result = _dynamic_secrets()
        assert isinstance(result, list)
    finally:
        socket.gethostname = orig


def test_dynamic_secrets_getpass_error_handled() -> None:
    """Lines 49-50: getpass.getuser raising is caught."""
    import getpass

    from webscan.anonymize import _dynamic_secrets

    orig = getpass.getuser
    getpass.getuser = lambda: (_ for _ in ()).throw(Exception("no user"))
    try:
        result = _dynamic_secrets()
        assert isinstance(result, list)
    finally:
        getpass.getuser = orig


def test_dynamic_secrets_short_values_filtered() -> None:
    """Values <= 2 chars are filtered out (too ambiguous to scrub)."""
    import getpass
    import socket

    from webscan.anonymize import _dynamic_secrets

    orig_h = socket.gethostname
    orig_u = getpass.getuser
    socket.gethostname = lambda: "ab"  # length <= 2
    getpass.getuser = lambda: "x"    # length <= 2
    try:
        result = _dynamic_secrets()
        assert result == []
    finally:
        socket.gethostname = orig_h
        getpass.getuser = orig_u
