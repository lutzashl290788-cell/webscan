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

# ANSI 256-colour codes per severity for the coloured console summary.
_SEVERITY_ANSI: dict[Severity, str] = {
    Severity.CRITICAL: "\033[1;38;5;196m",
    Severity.HIGH:     "\033[1;38;5;208m",
    Severity.MEDIUM:   "\033[1;38;5;178m",
    Severity.LOW:      "\033[1;38;5;33m",
    Severity.INFO:     "\033[1;38;5;245m",
}
_ANSI_RESET = "\033[0m"
_ANSI_DIM = "\033[2m"


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
    # HTML
    # ------------------------------------------------------------------

    def to_html(self, output_path: Path | None = None) -> str:
        """Render a self-contained HTML report (inline CSS, no external assets).

        :param output_path: If provided, the HTML string is also written here.
        :returns: HTML string.
        """
        r = self.report
        totals = _count_severities(
            [f for tr in r.targets for f in tr.findings]
        )

        parts: list[str] = [
            "<!DOCTYPE html>",
            '<html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>WebScan Report — {_esc(r.scan_started)}</title>",
            f"<style>{_HTML_CSS}</style></head><body>",
            '<div class="wrap">',
            "<h1>🔍 WebScan Security Report</h1>",
            '<div class="meta">',
            f"<span>Started: <code>{_esc(r.scan_started)}</code></span>",
            f"<span>Finished: <code>{_esc(r.scan_finished)}</code></span>",
            f"<span>Targets: <strong>{len(r.targets)}</strong></span>",
            f"<span>Findings: <strong>{r.total_findings}</strong></span>",
            "</div>",
            '<div class="counts">',
        ]

        for sev in Severity:
            parts.append(
                f'<span class="pill {sev.value}">{sev.value.upper()}'
                f" · {totals[sev]}</span>"
            )
        parts.append("</div>")

        for tr in r.targets:
            parts.append(f'<section><h2>🌐 {_esc(tr.target)}</h2>')
            if tr.errors:
                parts.append('<div class="errors"><strong>Errors</strong><ul>')
                parts.extend(f"<li>{_esc(e)}</li>" for e in tr.errors)
                parts.append("</ul></div>")

            if not tr.findings:
                parts.append('<p class="ok">✅ No issues detected.</p></section>')
                continue

            sorted_findings = sorted(
                tr.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
            )
            for f in sorted_findings:
                parts.append(self._finding_html(f))
            parts.append("</section>")

        parts.append("</div></body></html>")
        html_str = "".join(parts)

        if output_path is not None:
            output_path.write_text(html_str, encoding="utf-8")
        return html_str

    def _finding_html(self, f: Finding) -> str:
        sev = f.severity.value
        evidence = ""
        if f.evidence:
            dumped = json.dumps(f.evidence, indent=2, default=_json_default)
            evidence = f"<pre>{_esc(dumped)}</pre>"
        remediation = ""
        if f.remediation:
            remediation = (
                f'<p class="rem"><strong>Remediation:</strong> '
                f"{_esc(f.remediation)}</p>"
            )
        return (
            f'<article class="finding {sev}">'
            f'<div class="fh"><span class="badge {sev}">{sev.upper()}</span>'
            f"<span class=\"ftitle\">{_esc(f.title)}</span></div>"
            f'<div class="fmeta"><code>{_esc(f.plugin)}</code> · '
            f'<a href="{_esc(f.url)}">{_esc(f.url)}</a></div>'
            f"<p>{_esc(f.description)}</p>{evidence}{remediation}</article>"
        )

    # ------------------------------------------------------------------
    # Console summary (plain text)
    # ------------------------------------------------------------------

    def to_console_summary(
        self,
        color: bool = False,
        min_severity: Severity | None = None,
    ) -> str:
        """One-line-per-finding text for terminal output.

        :param color: Wrap severities in ANSI colour codes.
        :param min_severity: Hide findings less severe than this level.
        """
        threshold = SEVERITY_ORDER.get(min_severity, 99) if min_severity else 99
        lines: list[str] = []
        for tr in self.report.targets:
            shown = [
                f
                for f in tr.findings
                if SEVERITY_ORDER.get(f.severity, 99) <= threshold
            ]
            header = f"[{tr.target}]"
            if not shown and not tr.errors:
                lines.append(f"  ✓ {header} — no findings")
                continue
            lines.append(f"  • {header}")
            sorted_findings = sorted(
                shown,
                key=lambda f: SEVERITY_ORDER.get(f.severity, 99),
            )
            for f in sorted_findings:
                badge = _SEVERITY_BADGE.get(f.severity, "?       ")
                emoji = _SEVERITY_EMOJI.get(f.severity, " ")
                if color:
                    tint = _SEVERITY_ANSI.get(f.severity, "")
                    lines.append(
                        f"      {emoji} {tint}[{badge}]{_ANSI_RESET} {f.title}"
                    )
                else:
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


def _esc(text: str) -> str:
    """HTML-escape a string for safe embedding in the report."""
    import html as _html

    return _html.escape(str(text), quote=True)


_HTML_CSS = """
*{box-sizing:border-box}body{margin:0;background:#0d1117;color:#e6edf3;
font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:32px 20px}
h1{font-size:24px;margin:0 0 16px}h2{font-size:18px;margin:28px 0 12px;
border-bottom:1px solid #21262d;padding-bottom:8px}
.meta{display:flex;flex-wrap:wrap;gap:16px;color:#8b949e;font-size:13px;
margin-bottom:16px}.meta code,code{background:#161b22;padding:2px 6px;
border-radius:4px;color:#79c0ff}
.counts{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:8px}
.pill,.badge{display:inline-block;padding:3px 10px;border-radius:20px;
font-size:12px;font-weight:600;color:#fff}
.critical{background:#da3633}.high{background:#db6d28}.medium{background:#d29922}
.low{background:#1f6feb}.info{background:#484f58}
.finding{background:#161b22;border:1px solid #21262d;border-left-width:4px;
border-radius:8px;padding:14px 16px;margin:10px 0}
.finding.critical{border-left-color:#da3633}.finding.high{border-left-color:#db6d28}
.finding.medium{border-left-color:#d29922}.finding.low{border-left-color:#1f6feb}
.finding.info{border-left-color:#484f58}
.fh{display:flex;align-items:center;gap:10px;margin-bottom:6px}
.ftitle{font-weight:600}.fmeta{font-size:13px;color:#8b949e;margin-bottom:8px}
.fmeta a{color:#79c0ff;text-decoration:none}
pre{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:10px;
overflow:auto;font-size:12px;color:#c9d1d9}
.rem{font-size:13px;color:#adbac7}.ok{color:#3fb950}
.errors{background:#2d1416;border:1px solid #5c2326;border-radius:6px;
padding:8px 12px;font-size:13px;color:#ff7b72}
.errors ul{margin:4px 0 0;padding-left:18px}
"""


def _count_severities(findings: list[Finding]) -> dict[Severity, int]:
    counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
