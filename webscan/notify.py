"""Webhook notifications — send scan summaries to Slack/Discord/Teams/HTTP.

After a scan completes, optionally POST a JSON summary to a webhook URL.
Supports Slack, Discord, Microsoft Teams, and generic HTTP webhooks.

Usage::

    from webscan.notify import send_webhook, build_slack_message

    # CLI: webscan -t https://example.com --webhook-url https://hooks.slack.com/...
    message = build_slack_message(report, risk_score=72, grade="C")
    await send_webhook("https://hooks.slack.com/...", message)
"""
from __future__ import annotations

from typing import Any

import aiohttp

from webscan.models import ScanReport, Severity


async def send_webhook(
    url: str,
    payload: dict[str, Any],
    *,
    timeout: float = 10.0,
) -> bool:
    """POST *payload* to *url*. Returns True on success, False on failure.

    Never raises — webhook failures are best-effort and should not abort the
    scan. Errors are swallowed and logged to stderr.
    """
    import sys

    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as session:
            async with session.post(url, json=payload) as resp:
                if resp.status >= 400:
                    print(
                        f"  Webhook: HTTP {resp.status} from {url[:60]}…",
                        file=sys.stderr,
                    )
                    return False
                return True
    except Exception as exc:  # noqa: BLE001 — best-effort, never fatal
        print(f"  Webhook: {exc}", file=sys.stderr)
        return False


def _sev_emoji(severity: str) -> str:
    """Slack/Discord emoji for a severity level."""
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }.get(severity.lower(), "⚪")


def build_slack_message(
    report: ScanReport,
    *,
    risk_score: float | None = None,
    grade: str | None = None,
    target: str = "",
) -> dict[str, Any]:
    """Build a Slack-formatted webhook payload.

    Works with Discord and Microsoft Teams too (they accept Slack-format JSON).
    """
    # Count findings by severity.
    counts: dict[str, int] = {}
    for tr in report.targets:
        for f in tr.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            counts[sev] = counts.get(sev, 0) + 1

    # Build the text summary.
    parts: list[str] = []
    parts.append("🛡️ *WebScan Security Report*")
    if target:
        parts.append(f"Target: `{target}`")
    parts.append(f"Findings: *{report.total_findings}*")

    if risk_score is not None:
        parts.append(f"Risk score: *{risk_score:.0f}/100* ({grade or '?'})")

    # Severity breakdown.
    sev_parts: list[str] = []
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            sev_parts.append(f"{_sev_emoji(sev)} {counts[sev]} {sev}")
    if sev_parts:
        parts.append("  ".join(sev_parts))

    # Top 3 findings.
    all_findings = [f for tr in report.targets for f in tr.findings]
    top = sorted(
        all_findings,
        key=lambda f: {
            Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3,
            Severity.LOW: 2, Severity.INFO: 1,
        }.get(f.severity, 0),
        reverse=True,
    )[:3]
    if top:
        parts.append("\n*Top findings:*")
        for f in top:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            parts.append(f"  {_sev_emoji(sev)} [{sev.upper()}] {f.plugin}: {f.title}")

    text = "\n".join(parts)

    return {
        "text": text,
        "username": "WebScan",
        "icon_emoji": ":shield:",
    }


def build_discord_message(
    report: ScanReport,
    *,
    risk_score: float | None = None,
    grade: str | None = None,
    target: str = "",
) -> dict[str, Any]:
    """Build a Discord-formatted webhook payload.

    Discord uses a different format than Slack — it wraps content in an embed.
    """
    counts: dict[str, int] = {}
    for tr in report.targets:
        for f in tr.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            counts[sev] = counts.get(sev, 0) + 1

    color_map = {
        "critical": 0xDC2626,  # red
        "high": 0xF87171,      # orange
        "medium": 0xFBBF24,    # yellow
        "low": 0x3B82F6,       # blue
        "info": 0x8B949E,      # grey
    }
    # Pick embed colour based on the worst severity.
    worst = 0x22C55E  # green = clean
    for sev in ("critical", "high", "medium", "low"):
        if counts.get(sev):
            worst = color_map.get(sev, worst)
            break

    desc_parts: list[str] = []
    if target:
        desc_parts.append(f"**Target:** `{target}`")
    desc_parts.append(f"**Findings:** {report.total_findings}")
    if risk_score is not None:
        desc_parts.append(f"**Risk score:** {risk_score:.0f}/100 ({grade or '?'})")

    sev_parts: list[str] = []
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            sev_parts.append(f"{_sev_emoji(sev)} {counts[sev]} {sev}")
    if sev_parts:
        desc_parts.append("  ".join(sev_parts))

    return {
        "username": "WebScan",
        "embeds": [
            {
                "title": "🛡️ WebScan Security Report",
                "description": "\n".join(desc_parts),
                "color": worst,
                "footer": {"text": "WebScan v2.8.1 · open-source DAST"},
            }
        ],
    }


def build_generic_payload(
    report: ScanReport,
    *,
    risk_score: float | None = None,
    grade: str | None = None,
    target: str = "",
) -> dict[str, Any]:
    """Build a generic JSON payload for any HTTP webhook endpoint.

    Contains the full structured report summary — the receiver can format it
    however they like.
    """
    findings: list[dict[str, str]] = []
    for tr in report.targets:
        for f in tr.findings:
            findings.append({
                "plugin": f.plugin,
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "confidence": f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                "url": f.url,
            })

    return {
        "scanner": "WebScan",
        "version": "2.8.1",
        "target": target,
        "scan_started": report.scan_started,
        "scan_finished": report.scan_finished,
        "total_findings": report.total_findings,
        "risk_score": round(risk_score, 1) if risk_score is not None else None,
        "grade": grade,
        "findings": findings,
    }


def detect_webhook_type(url: str) -> str:
    """Detect the webhook type from the URL.

    >>> detect_webhook_type("https://hooks.slack.com/services/T00/B00/xxx")
    'slack'
    >>> detect_webhook_type("https://discord.com/api/webhooks/123/abc")
    'discord'
    >>> detect_webhook_type("https://example.com/webhook")
    'generic'
    """
    url_lower = url.lower()
    if "hooks.slack.com" in url_lower:
        return "slack"
    if "discord.com/api/webhooks" in url_lower:
        return "discord"
    if "hooks.slace" in url_lower:  # typo guard
        return "slack"
    return "generic"


def build_webhook_payload(
    url: str,
    report: ScanReport,
    *,
    risk_score: float | None = None,
    grade: str | None = None,
    target: str = "",
) -> dict[str, Any]:
    """Build the appropriate payload based on the webhook URL.

    Auto-detects Slack/Discord/generic and uses the right format.
    """
    wtype = detect_webhook_type(url)
    if wtype == "slack":
        return build_slack_message(report, risk_score=risk_score, grade=grade, target=target)
    if wtype == "discord":
        return build_discord_message(report, risk_score=risk_score, grade=grade, target=target)
    return build_generic_payload(report, risk_score=risk_score, grade=grade, target=target)
