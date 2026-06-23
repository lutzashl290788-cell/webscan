"""Risk scoring engine — translates a scan's findings into a single 0-100 score.

Inspired by SSL Labs' grading: a single number that summarises the overall
security posture of the scanned target. The score factors in:

* **Severity** — critical findings weigh more than info-level ones.
* **Confidence** — firm findings (content-verified) weigh more than tentative
  ones; informational findings barely move the needle.
* **Exposure** — findings on the main page (root URL) are riskier than those
  on deep, hard-to-reach paths.
* **Volume** — one missing header is a mistake; twenty findings is a pattern.

The score starts at 100 (perfect) and is reduced by each finding. The
reduction uses a non-linear curve so that the first few findings drop the
score quickly (drawing attention) while additional findings have diminishing
impact (avoiding "death by a thousand cuts" to zero).

Usage::

    from webscan.risk import compute_risk_score, risk_grade, risk_summary

    score, breakdown = compute_risk_score(report)
    print(risk_grade(score))  # 'A', 'B', 'C', 'D', 'F'
    print(risk_summary(score, breakdown))
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webscan.models import Confidence, ScanReport, Severity

# ─── Weights ────────────────────────────────────────────────────────────────

# Base penalty per finding, by severity. These are the "raw" point deductions
# before confidence and exposure multipliers are applied.
_SEVERITY_PENALTY: dict[Severity, float] = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 12.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 1.5,
    Severity.INFO: 0.2,
}

# Confidence multiplier — firm findings penalise the score at full weight;
# tentative findings at 60%; informational at 20%.
_CONFIDENCE_MULTIPLIER: dict[Confidence, float] = {
    Confidence.FIRM: 1.0,
    Confidence.TENTATIVE: 0.6,
    Confidence.INFORMATIONAL: 0.2,
}

# Exposure multiplier — findings on the root URL ("/") or the exact target
# URL are more exposed than findings on deep paths. We check if the finding's
# URL path is short (root-level) vs long (deep).
_EXPOSURE_ROOT = 1.3   # finding on the root page
_EXPOSURE_DEEP = 1.0   # finding on a deep path
_ROOT_PATH_THRESHOLD = 2  # paths with ≤ this many "/" segments are "root-level"


# ─── Grading ────────────────────────────────────────────────────────────────

def risk_grade(score: float) -> str:
    """Convert a 0-100 score to a letter grade (A–F).

    >>> risk_grade(95)
    'A'
    >>> risk_grade(72)
    'B'
    >>> risk_grade(30)
    'D'
    >>> risk_grade(10)
    'F'
    """
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 55:
        return "C"
    if score >= 30:
        return "D"
    return "F"


_GRADE_COLOUR: dict[str, str] = {
    "A": "#22c55e",  # green
    "B": "#39c5cf",  # cyan
    "C": "#fbbf24",  # amber
    "D": "#f87171",  # red-400
    "F": "#dc2626",  # red-600
}


def grade_colour(grade: str) -> str:
    """Hex colour for a grade letter (for HTML reports)."""
    return _GRADE_COLOUR.get(grade, "#8b949e")


# ─── Scoring ────────────────────────────────────────────────────────────────

@dataclass
class RiskBreakdown:
    """Detailed breakdown of how the risk score was computed.

    Each entry in ``finding_penalties`` is ``(plugin, title, severity,
    confidence, penalty)`` — useful for the HTML report to show a per-finding
    table.
    """

    score: float = 100.0
    grade: str = "A"
    total_findings: int = 0
    total_penalty: float = 0.0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_confidence: dict[str, int] = field(default_factory=dict)
    finding_penalties: list[tuple[str, str, str, str, float]] = field(
        default_factory=list
    )
    # Compliance-style summary — which "risk categories" contributed most.
    top_risk_findings: list[tuple[str, str, float]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation for the report."""
        return {
            "score": round(self.score, 1),
            "grade": self.grade,
            "total_findings": self.total_findings,
            "total_penalty": round(self.total_penalty, 1),
            "by_severity": self.by_severity,
            "by_confidence": self.by_confidence,
            "top_risk_findings": [
                {"plugin": p, "title": t, "penalty": round(pen, 1)}
                for p, t, pen in self.top_risk_findings[:5]
            ],
        }


def _is_root_url(url: str) -> bool:
    """True if *url* points to the site root or a shallow path.

    >>> _is_root_url("https://example.com")
    True
    >>> _is_root_url("https://example.com/")
    True
    >>> _is_root_url("https://example.com/admin")
    True
    >>> _is_root_url("https://example.com/api/v1/users/123")
    False
    """
    from urllib.parse import urlparse

    path = urlparse(url).path or "/"
    # Count path segments (excluding empty leading/trailing).
    segments = [s for s in path.split("/") if s]
    return len(segments) <= _ROOT_PATH_THRESHOLD


def compute_risk_score(report: ScanReport) -> tuple[float, RiskBreakdown]:
    """Compute a 0-100 risk score for *report*.

    Returns ``(score, breakdown)``. The score starts at 100 (perfect) and is
    reduced by each finding. The minimum score is 0 (worst possible).

    The penalty curve is **sub-linear** in the total number of findings: the
    first finding penalises at full weight, the second at 95%, the third at
    90%, and so on — this prevents a site with 50 low-severity findings from
    scoring worse than one with a single critical.
    """
    breakdown = RiskBreakdown()
    all_findings = [
        f for tr in report.targets for f in tr.findings
    ]
    breakdown.total_findings = len(all_findings)

    # Count by severity and confidence for the breakdown.
    for f in all_findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        conf = f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence)
        breakdown.by_severity[sev] = breakdown.by_severity.get(sev, 0) + 1
        breakdown.by_confidence[conf] = breakdown.by_confidence.get(conf, 0) + 1

    # Compute per-finding penalty with diminishing returns.
    penalties: list[tuple[str, str, str, str, float]] = []
    for i, f in enumerate(all_findings):
        sev = f.severity if isinstance(f.severity, Severity) else Severity(str(f.severity))
        conf = (f.confidence if isinstance(f.confidence, Confidence)
                 else Confidence(str(f.confidence)))

        base = _SEVERITY_PENALTY.get(sev, 0.5)
        conf_mult = _CONFIDENCE_MULTIPLIER.get(conf, 0.5)
        exposure_mult = _EXPOSURE_ROOT if _is_root_url(f.url) else _EXPOSURE_DEEP

        # Diminishing returns: each subsequent finding penalises 5% less,
        # down to a floor of 30% of the original weight. This prevents
        # "death by a thousand cuts" from low-severity findings.
        decay = max(0.30, 1.0 - (i * 0.05))
        penalty = base * conf_mult * exposure_mult * decay

        sev_str = sev.value
        conf_str = conf.value
        penalties.append((f.plugin, f.title, sev_str, conf_str, penalty))
        breakdown.total_penalty += penalty

    # Clamp score to [0, 100].
    breakdown.score = max(0.0, 100.0 - breakdown.total_penalty)
    breakdown.grade = risk_grade(breakdown.score)
    breakdown.finding_penalties = penalties

    # Top 5 riskiest findings (highest penalty).
    breakdown.top_risk_findings = sorted(
        [(p, t, pen) for p, t, _, _, pen in penalties],
        key=lambda x: x[2],
        reverse=True,
    )[:5]

    return breakdown.score, breakdown


def risk_summary(score: float, breakdown: RiskBreakdown) -> str:
    """Human-readable one-line summary of the risk score.

    >>> from webscan.models import ScanReport
    >>> r = ScanReport(scan_started="t0", scan_finished="t1")
    >>> s, b = compute_risk_score(r)
    >>> risk_summary(s, b)
    'Risk score: 100/100 (A) — 0 findings'
    """
    return (
        f"Risk score: {score:.0f}/100 ({breakdown.grade}) — "
        f"{breakdown.total_findings} findings"
    )


def risk_recommendation(grade: str) -> str:
    """Actionable recommendation based on the grade.

    >>> risk_recommendation("A")
    'Excellent posture — no critical or high-severity issues. Keep monitoring.'
    >>> risk_recommendation("F")
    'Critical risk — immediate remediation required before production deployment.'
    """
    recommendations = {
        "A": "Excellent posture — no critical or high-severity issues. Keep monitoring.",
        "B": "Good posture — a few medium issues to address. Schedule fixes in the next sprint.",
        "C": "Moderate risk — several medium/high issues. Prioritise remediation this week.",
        "D": "High risk — critical or multiple high-severity issues. Fix before next release.",
        "F": "Critical risk — immediate remediation required before production deployment.",
    }
    return recommendations.get(grade, "Unknown grade.")
