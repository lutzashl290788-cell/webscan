"""Report anonymisation — strip locally-identifying data before export.

When enabled (``--anonymize``), report content is scrubbed of information that
could deanonymise the operator or leak internal infrastructure: local
filesystem paths, the machine hostname / OS username, and RFC 1918 / loopback
IP addresses. Useful for sharing SARIF/JSON externally and for GDPR-friendly
data minimisation.
"""
from __future__ import annotations

import getpass
import re
import socket
from dataclasses import replace

from webscan.models import Finding, ScanReport, TargetResult

# RFC 1918 private ranges, loopback and link-local — replaced with a redaction.
_PRIVATE_IP = re.compile(
    r"\b("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r")\b"
)

# Unix and Windows home-directory paths, e.g. /home/alice/... or C:\Users\alice\...
_UNIX_HOME = re.compile(r"/(?:home|Users)/[^/\s\"']+")
_WIN_HOME = re.compile(r"[A-Za-z]:\\Users\\[^\\\s\"']+", re.IGNORECASE)

_REDACTED = "[REDACTED]"


def _dynamic_secrets() -> list[str]:
    """Collect machine-specific tokens to scrub (hostname, username)."""
    secrets: list[str] = []
    try:
        host = socket.gethostname()
        if host and len(host) > 2:
            secrets.append(host)
    except OSError:
        pass
    try:
        user = getpass.getuser()
        if user and len(user) > 2:
            secrets.append(user)
    except Exception:  # noqa: BLE001 — getuser can raise on odd environments
        pass
    return secrets


def _scrub(text: str, secrets: list[str]) -> str:
    if not text:
        return text
    text = _WIN_HOME.sub(r"[REDACTED_PATH]", text)
    text = _UNIX_HOME.sub("/[REDACTED_PATH]", text)
    text = _PRIVATE_IP.sub("[REDACTED_IP]", text)
    for secret in secrets:
        text = text.replace(secret, _REDACTED)
    return text


def _scrub_value(value: object, secrets: list[str]) -> object:
    if isinstance(value, str):
        return _scrub(value, secrets)
    if isinstance(value, dict):
        return {k: _scrub_value(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_value(v, secrets) for v in value]
    return value


def _scrub_finding(finding: Finding, secrets: list[str]) -> Finding:
    return replace(
        finding,
        title=_scrub(finding.title, secrets),
        description=_scrub(finding.description, secrets),
        url=_scrub(finding.url, secrets),
        remediation=_scrub(finding.remediation, secrets),
        evidence=_scrub_value(finding.evidence, secrets),  # type: ignore[arg-type]
    )


def anonymize_report(report: ScanReport) -> ScanReport:
    """Return a deep-scrubbed copy of *report* safe for external sharing."""
    secrets = _dynamic_secrets()

    new_targets: list[TargetResult] = []
    for tr in report.targets:
        new_targets.append(
            TargetResult(
                target=_scrub(tr.target, secrets),
                findings=[_scrub_finding(f, secrets) for f in tr.findings],
                errors=[_scrub(e, secrets) for e in tr.errors],
                scanned_at=tr.scanned_at,
            )
        )

    return ScanReport(
        scan_started=report.scan_started,
        scan_finished=report.scan_finished,
        total_findings=report.total_findings,
        targets=new_targets,
    )
