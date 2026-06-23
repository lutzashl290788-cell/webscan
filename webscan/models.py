"""Data models for WebScan findings and reports."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Finding severity levels, ordered from most to least critical."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Confidence(str, Enum):
    """How sure a plugin is that a finding is real (not a false positive).

    Severity answers "how bad if true"; confidence answers "how likely true".
    Separating the two lets a user filter out noise (``--min-confidence firm``)
    without lowering the severity bar, so a tentative-but-critical result is
    still surfaced — just marked as needing confirmation.
    """

    #: Directly observed / proven (e.g. payload reflected unescaped, DB error
    #: returned, header literally absent). Very low false-positive rate.
    FIRM = "firm"
    #: Heuristic or inferred — a strong signal that still warrants manual
    #: confirmation (version-based CVE guesses, timing-based blind SQLi, etc.).
    TENTATIVE = "tentative"
    #: Informational / best-practice note rather than a confirmed weakness.
    INFORMATIONAL = "informational"


CONFIDENCE_ORDER: dict[Confidence, int] = {
    Confidence.FIRM: 0,
    Confidence.TENTATIVE: 1,
    Confidence.INFORMATIONAL: 2,
}


@dataclass
class Finding:
    """A single security finding produced by a plugin."""

    plugin: str
    title: str
    severity: Severity
    description: str
    url: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    #: How likely this finding is a true positive. Defaults to FIRM so existing
    #: plugins that observe a condition directly need no change; heuristic
    #: checks downgrade to TENTATIVE / INFORMATIONAL explicitly.
    confidence: Confidence = Confidence.FIRM


@dataclass
class TargetResult:
    """Aggregated scan results for a single target URL."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scanned_at: str = ""


@dataclass
class ScanReport:
    """Top-level report covering all scanned targets."""

    scan_started: str = ""
    scan_finished: str = ""
    total_findings: int = 0
    targets: list[TargetResult] = field(default_factory=list)
