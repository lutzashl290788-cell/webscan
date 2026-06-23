"""Diff engine — compare two scan reports and surface what changed.

Used by ``webscan diff old.json new.json`` to show:

* **New findings** (regressions) — present in the new report but not the old.
* **Fixed findings** — present in the old report but not the new.
* **Changed findings** — same plugin+title but severity or confidence shifted.

This is the killer feature for CI: point it at the baseline report and the
current scan, and it tells you whether your PR introduced new vulnerabilities
or fixed existing ones. Exit code 1 if any new HIGH/CRITICAL finding appeared.

Usage::

    from webscan.diff import diff_reports, DiffResult

    result = diff_reports(old_report, new_report)
    for f in result.new_findings:
        print(f"NEW: {f.plugin}: {f.title}")
    for f in result.fixed_findings:
        print(f"FIXED: {f.plugin}: {f.title}")
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webscan.models import Finding, ScanReport, Severity

# A finding's "identity" for diff purposes: (plugin, title, url).
# Two findings with the same identity are considered "the same issue" even
# if the severity or confidence changed.
FindingKey = tuple[str, str, str]


@dataclass
class ChangedFinding:
    """A finding that exists in both reports but with different severity/confidence."""
    plugin: str
    title: str
    url: str
    old_severity: Severity
    new_severity: Severity
    old_confidence: str
    new_confidence: str

    @property
    def severity_changed(self) -> bool:
        """True if severity increased or decreased."""
        return self.old_severity != self.new_severity

    @property
    def severity_increased(self) -> bool:
        """True if severity went UP (e.g. medium → high)."""
        order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        old_val = self.old_severity.value if hasattr(self.old_severity, "value") else str(self.old_severity)
        new_val = self.new_severity.value if hasattr(self.new_severity, "value") else str(self.new_severity)
        return order.get(str(new_val).lower(), 0) > order.get(str(old_val).lower(), 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin": self.plugin,
            "title": self.title,
            "url": self.url,
            "old_severity": self.old_severity.value if hasattr(self.old_severity, "value") else str(self.old_severity),
            "new_severity": self.new_severity.value if hasattr(self.new_severity, "value") else str(self.new_severity),
            "old_confidence": self.old_confidence,
            "new_confidence": self.new_confidence,
            "severity_increased": self.severity_increased,
        }


@dataclass
class DiffResult:
    """Result of comparing two scan reports."""
    new_findings: list[Finding] = field(default_factory=list)
    fixed_findings: list[Finding] = field(default_factory=list)
    changed_findings: list[ChangedFinding] = field(default_factory=list)
    unchanged_count: int = 0

    @property
    def has_regressions(self) -> bool:
        """True if any new CRITICAL or HIGH finding appeared."""
        return any(
            f.severity in (Severity.CRITICAL, Severity.HIGH)
            for f in self.new_findings
        )

    @property
    def has_improvements(self) -> bool:
        """True if any finding was fixed or severity decreased."""
        return len(self.fixed_findings) > 0 or any(
            c.severity_changed and not c.severity_increased
            for c in self.changed_findings
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "new_findings": [
                {"plugin": f.plugin, "title": f.title, "severity": f.severity.value,
                 "confidence": f.confidence.value, "url": f.url}
                for f in self.new_findings
            ],
            "fixed_findings": [
                {"plugin": f.plugin, "title": f.title, "severity": f.severity.value,
                 "confidence": f.confidence.value, "url": f.url}
                for f in self.fixed_findings
            ],
            "changed_findings": [c.to_dict() for c in self.changed_findings],
            "unchanged_count": self.unchanged_count,
            "has_regressions": self.has_regressions,
            "has_improvements": self.has_improvements,
        }


def _finding_key(f: Finding) -> FindingKey:
    """Extract the identity key for a finding (plugin, title, url)."""
    return (f.plugin, f.title, f.url)


def diff_reports(
    old: ScanReport,
    new: ScanReport,
) -> DiffResult:
    """Compare two scan reports and return what changed.

    :param old: The baseline report (e.g. from the last CI run).
    :param new: The current report (e.g. from this PR's scan).
    :returns: A :class:`DiffResult` with new/fixed/changed findings.
    """
    result = DiffResult()

    # Build a lookup of old findings by identity key.
    old_map: dict[FindingKey, Finding] = {}
    for tr in old.targets:
        for f in tr.findings:
            old_map[_finding_key(f)] = f

    new_map: dict[FindingKey, Finding] = {}
    for tr in new.targets:
        for f in tr.findings:
            new_map[_finding_key(f)] = f

    # Find new and changed findings.
    for key, new_finding in new_map.items():
        old_finding = old_map.get(key)
        if old_finding is None:
            # Not in old → new finding (regression).
            result.new_findings.append(new_finding)
        else:
            # In both → check if severity or confidence changed.
            old_sev = old_finding.severity
            new_sev = new_finding.severity
            old_conf = old_finding.confidence.value if hasattr(old_finding.confidence, "value") else str(old_finding.confidence)
            new_conf = new_finding.confidence.value if hasattr(new_finding.confidence, "value") else str(new_finding.confidence)
            if old_sev != new_sev or old_conf != new_conf:
                result.changed_findings.append(ChangedFinding(
                    plugin=new_finding.plugin,
                    title=new_finding.title,
                    url=new_finding.url,
                    old_severity=old_sev,
                    new_severity=new_sev,
                    old_confidence=old_conf,
                    new_confidence=new_conf,
                ))
            else:
                result.unchanged_count += 1

    # Find fixed findings (in old but not in new).
    for key, old_finding in old_map.items():
        if key not in new_map:
            result.fixed_findings.append(old_finding)

    return result


def format_diff(result: DiffResult, *, use_color: bool = False) -> str:
    """Format a DiffResult as a human-readable string for the CLI."""
    lines: list[str] = []
    lines.append("─" * 60)
    lines.append(f"  Scan diff: {len(result.new_findings)} new · "
                 f"{len(result.fixed_findings)} fixed · "
                 f"{len(result.changed_findings)} changed · "
                 f"{result.unchanged_count} unchanged")
    lines.append("─" * 60)

    if result.new_findings:
        lines.append("\n  🔴 NEW findings (regressions):")
        for f in result.new_findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            lines.append(f"    [{sev.upper():8}] {f.plugin}: {f.title}")
            lines.append(f"             {f.url}")

    if result.fixed_findings:
        lines.append("\n  🟢 FIXED findings (improvements):")
        for f in result.fixed_findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            lines.append(f"    [{sev.upper():8}] {f.plugin}: {f.title}")

    if result.changed_findings:
        lines.append("\n  🟡 CHANGED findings:")
        for c in result.changed_findings:
            old_s = c.old_severity.value if hasattr(c.old_severity, "value") else str(c.old_severity)
            new_s = c.new_severity.value if hasattr(c.new_severity, "value") else str(c.new_severity)
            arrow = "↑" if c.severity_increased else "↓"
            lines.append(f"    {c.plugin}: {c.title}")
            lines.append(f"      {old_s} {arrow} {new_s}")

    if not result.new_findings and not result.fixed_findings and not result.changed_findings:
        lines.append("\n  ✅ No changes — the security posture is identical to the baseline.")

    lines.append("")
    return "\n".join(lines)
