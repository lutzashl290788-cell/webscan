"""Report generation: JSON and Markdown output from a :class:`ScanReport`."""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from webscan.models import SEVERITY_ORDER, Finding, ScanReport, Severity

# Console / Markdown severity decorators
_SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

_SEVERITY_BADGE: dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH:     "HIGH    ",
    Severity.MEDIUM:   "MEDIUM  ",
    Severity.LOW:      "LOW     ",
    Severity.INFO:     "INFO    ",
}


class Reporter:
    """Renders a :class:`~webscan.models.ScanReport` in one or more formats."""

    def __init__(self, report: ScanReport) -> None:
        self.report = report

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def to_json(self, output_path: Path | None = None) -> str:
        """Serialise the full report to JSON.

        :param output_path: If provided, the JSON string is also written here.
        :returns: JSON string.
        """
        raw = asdict(self.report)
        json_str = json.dumps(raw, indent=2, ensure_ascii=False, default=_json_default)
        if output_path is not None:
            output_path.write_text(json_str, encoding="utf-8")
        return json_str

    # ------------------------------------------------------------------
    # Markdown
    # ------------------------------------------------------------------

    def to_markdown(self, output_path: Path | None = None) -> str:
        """Render the report as a Markdown document.

        :param output_path: If provided, the Markdown string is also written here.
        :returns: Markdown string.
        """
        lines: list[str] = []
        r = self.report

        # ---- Header ----
        lines += [
            "# 🔍 WebScan Security Report",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| Scan started  | `{r.scan_started}` |",
            f"| Scan finished | `{r.scan_finished}` |",
            f"| Targets scanned | **{len(r.targets)}** |",
            f"| Total findings  | **{r.total_findings}** |",
            "",
        ]

        # ---- Summary table ----
        lines += [
            "## Summary",
            "",
            "| Target | 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low | ⚪ Info | Errors |",
            "|--------|:-----------:|:-------:|:---------:|:------:|:-------:|:------:|",
        ]
        for tr in r.targets:
            counts = _count_severities(tr.findings)
            lines.append(
                f"| `{tr.target}` "
                f"| {counts[Severity.CRITICAL]} "
                f"| {counts[Severity.HIGH]} "
                f"| {counts[Severity.MEDIUM]} "
                f"| {counts[Severity.LOW]} "
                f"| {counts[Severity.INFO]} "
                f"| {len(tr.errors)} |"
            )
        lines.append("")

        # ---- Per-target details ----
        lines.append("## Detailed Findings")
        lines.append("")

        for tr in r.targets:
            lines += [
                f"### 🌐 {tr.target}",
                "",
                f"*Scanned at: `{tr.scanned_at}`*",
                "",
            ]

            if tr.errors:
                lines.append("#### ⚠️ Scan Errors")
                for err in tr.errors:
                    lines.append(f"- `{err}`")
                lines.append("")

            if not tr.findings:
                lines += ["✅ **No issues detected.**", ""]
                continue

            sorted_findings = sorted(
                tr.findings,
                key=lambda f: SEVERITY_ORDER.get(f.severity, 99),
            )

            for i, f in enumerate(sorted_findings, 1):
                emoji = _SEVERITY_EMOJI.get(f.severity, "⚪")
                badge = f.severity.value.upper()
                lines += [
                    f"#### {i}. {emoji} `[{badge}]` {f.title}",
                    "",
                    "| | |",
                    "|---|---|",
                    f"| **Plugin** | `{f.plugin}` |",
                    f"| **URL** | {f.url} |",
                    "",
                    f"**Description:** {f.description}",
                    "",
                ]

                if f.evidence:
                    lines += [
                        "**Evidence:**",
                        "```json",
                        json.dumps(f.evidence, indent=2, default=_json_default),
                        "```",
                        "",
                    ]

                if f.remediation:
                    lines += [
                        f"**Remediation:** {f.remediation}",
                        "",
                    ]

                lines.append("---")
                lines.append("")

        md_str = "\n".join(lines)
        if output_path is not None:
            output_path.write_text(md_str, encoding="utf-8")
        return md_str

    # ------------------------------------------------------------------
    # Console summary (plain text)
    # ------------------------------------------------------------------

    def to_console_summary(self) -> str:
        """One-line-per-finding text for terminal output."""
        lines: list[str] = []
        for tr in self.report.targets:
            header = f"[{tr.target}]"
            if not tr.findings and not tr.errors:
                lines.append(f"  ✓ {header} — no findings")
                continue
            lines.append(f"  • {header}")
            sorted_findings = sorted(
                tr.findings,
                key=lambda f: SEVERITY_ORDER.get(f.severity, 99),
            )
            for f in sorted_findings:
                badge = _SEVERITY_BADGE.get(f.severity, "?       ")
                emoji = _SEVERITY_EMOJI.get(f.severity, " ")
                lines.append(f"      {emoji} [{badge}] {f.title}")
            for err in tr.errors:
                lines.append(f"      ⚡ [ERROR   ] {err}")
        return "\n".join(lines)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _json_default(obj: Any) -> Any:  # noqa: ANN401 — generic JSON fallback
    """Fallback JSON serialiser for non-standard types."""
    if hasattr(obj, "value"):  # Enum
        return obj.value
    return str(obj)


def _count_severities(findings: list[Finding]) -> dict[Severity, int]:
    counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
