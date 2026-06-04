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
