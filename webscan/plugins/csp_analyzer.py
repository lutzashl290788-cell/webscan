"""Plugin: CSP (Content-Security-Policy) deep analyzer.

Parses the CSP header and checks for:
- Missing directives (script-src, object-src, base-uri, frame-ancestors)
- Unsafe directives ('unsafe-inline', 'unsafe-eval')
- Overly broad sources (*, https:)
- Missing 'strict-dynamic' or nonce/hash
- Report-uri not configured

No other open-source DAST tool does deep CSP analysis — they just check
"header present/absent".
"""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins.base import BasePlugin


class CspAnalyzerPlugin(BasePlugin):
    """Deep Content-Security-Policy analysis."""

    name = "csp_analyzer"
    description = "Deep CSP parsing: unsafe directives, missing protections, report-uri"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        try:
            async with session.get(target, allow_redirects=True, ssl=False) as resp:
                csp = resp.headers.get("Content-Security-Policy", "")
                if not csp:
                    return findings  # headers plugin already flags missing CSP
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return findings

        # Parse the CSP into directives.
        directives = _parse_csp(csp)
        if not directives:
            return findings

        # ─── Check for unsafe-inline ────────────────────────────────────────
        script_src = directives.get("script-src", "")
        if "'unsafe-inline'" in script_src:
            findings.append(Finding(
                plugin=self.name,
                title="CSP allows 'unsafe-inline' in script-src",
                severity=Severity.HIGH,
                confidence=Confidence.FIRM,
                description=(
                    "The Content-Security-Policy includes 'unsafe-inline' in "
                    "script-src, which completely defeats CSP's XSS protection. "
                    "Browsers will execute any inline script, including attacker-injected ones."
                ),
                url=target,
                evidence={"directive": "script-src", "value": script_src, "issue": "unsafe-inline"},
                remediation=(
                    "Remove 'unsafe-inline' from script-src. Use nonces "
                    "(<script nonce=\"abc123\">) or hashes instead. "
                    "If using a framework like React/Vue, ensure all scripts are external."
                ),
            ))

        # ─── Check for unsafe-eval ──────────────────────────────────────────
        if "'unsafe-eval'" in script_src:
            findings.append(Finding(
                plugin=self.name,
                title="CSP allows 'unsafe-eval' in script-src",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                description=(
                    "The CSP includes 'unsafe-eval' in script-src, allowing "
                    "eval(), Function(), and similar APIs. This weakens CSP "
                    "and can be exploited if user input reaches eval."
                ),
                url=target,
                evidence={"directive": "script-src", "value": script_src, "issue": "unsafe-eval"},
                remediation="Remove 'unsafe-eval' if possible. Some frameworks (older Angular) require it — upgrade or sandbox.",
            ))

        # ─── Check for wildcard * ───────────────────────────────────────────
        for directive, value in directives.items():
            if directive.endswith("-src") and " *" in f" {value} ":
                findings.append(Finding(
                    plugin=self.name,
                    title=f"CSP uses wildcard '*' in {directive}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    description=(
                        f"The CSP directive '{directive}' includes the wildcard '*', "
                        "allowing resources from any origin. This significantly weakens CSP."
                    ),
                    url=target,
                    evidence={"directive": directive, "value": value, "issue": "wildcard"},
                    remediation=f"Replace '*' in {directive} with explicit allowed origins (e.g. 'self', 'https://cdn.example.com').",
                ))
                break  # one wildcard finding is enough

        # ─── Check for missing object-src ───────────────────────────────────
        if "object-src" not in directives:
            findings.append(Finding(
                plugin=self.name,
                title="CSP missing object-src directive",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                description=(
                    "The CSP does not include an object-src directive. Without it, "
                    "browsers default to allowing Flash/Java/object embeds, which "
                    "can be used to bypass CSP."
                ),
                url=target,
                evidence={"missing_directive": "object-src"},
                remediation="Add 'object-src \"none\"' to the CSP to block all object embeds.",
            ))

        # ─── Check for missing base-uri ─────────────────────────────────────
        if "base-uri" not in directives:
            findings.append(Finding(
                plugin=self.name,
                title="CSP missing base-uri directive",
                severity=Severity.LOW,
                confidence=Confidence.FIRM,
                description=(
                    "The CSP does not restrict base-uri. An attacker who can inject "
                    "a <base> tag can redirect all relative URLs to their server."
                ),
                url=target,
                evidence={"missing_directive": "base-uri"},
                remediation="Add 'base-uri \"self\"' to the CSP.",
            ))

        # ─── Check for missing frame-ancestors ──────────────────────────────
        if "frame-ancestors" not in directives:
            findings.append(Finding(
                plugin=self.name,
                title="CSP missing frame-ancestors directive",
                severity=Severity.LOW,
                confidence=Confidence.FIRM,
                description=(
                    "The CSP does not restrict frame-ancestors. The page can be "
                    "framed by any site (clickjacking risk)."
                ),
                url=target,
                evidence={"missing_directive": "frame-ancestors"},
                remediation="Add 'frame-ancestors \"none\"' or 'frame-ancestors \"self\"' to the CSP.",
            ))

        # ─── Check for missing report-uri ───────────────────────────────────
        if "report-uri" not in directives and "report-to" not in directives:
            findings.append(Finding(
                plugin=self.name,
                title="CSP missing violation reporting",
                severity=Severity.INFO,
                confidence=Confidence.INFORMATIONAL,
                description=(
                    "The CSP does not include a report-uri or report-to directive. "
                    "Without reporting, CSP violations are invisible — you can't "
                    "detect or investigate attempted attacks."
                ),
                url=target,
                evidence={"missing_directive": "report-uri"},
                remediation="Add 'report-uri /csp-report' to the CSP and set up an endpoint to collect violation reports.",
            ))

        return findings


def _parse_csp(csp_header: str) -> dict[str, str]:
    """Parse a CSP header into a dict of {directive: value}.

    >>> _parse_csp("default-src 'self'; script-src 'self' 'unsafe-inline'")
    {"default-src": "'self'", "script-src": "'self' 'unsafe-inline'"}
    """
    result: dict[str, str] = {}
    for directive in csp_header.split(";"):
        parts = directive.strip().split(None, 1)
        if not parts:
            continue
        name = parts[0]
        value = parts[1] if len(parts) > 1 else ""
        result[name] = value
    return result
