"""Plugin: detect verbose error pages and debug mode exposure.

Many frameworks expose detailed error pages in development mode that leak
stack traces, file paths, environment variables, and internal state. In
production, these should be disabled. This plugin passively inspects the
response body for known error-page signatures.

Findings:

* **MEDIUM (FIRM)** — response contains a stack trace or framework-specific
  debug page marker. FIRM because these markers are unambiguous.
* **LOW (INFORMATIONAL)** — response contains a generic error message that
  *might* indicate debug mode (e.g. ``Debug mode is on``) but doesn't leak
  a stack trace.

The plugin is fully passive — it only inspects the response the server
already returned.
"""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins._active_helpers import fetch_body
from webscan.plugins.base import BasePlugin

# ─── Detection rules ─────────────────────────────────────────────────────────

# Stack-trace markers — unambiguous signs of a verbose error page.
# Each entry: (marker, framework_name).
_STACK_TRACE_MARKERS: tuple[tuple[str, str], ...] = (
    ("Traceback (most recent call last)", "Python"),
    ("File \"", "Python/Java"),
    ("at org.springframework", "Spring Boot (Java)"),
    ("at java.lang", "Java"),
    ("at sun.reflect", "Java"),
    ("NullPointerException", "Java"),
    ("at com.", "Java"),
    ("PHP Fatal error", "PHP"),
    ("PHP Parse error", "PHP"),
    ("PHP Notice:", "PHP"),
    ("PHP Warning:", "PHP"),
    ("Stack trace:", "Generic"),
    ("#0 ", "PHP/Ruby stack frame"),
    ("Traceback:", "Python/Django"),
    ("django.core.exceptions", "Django"),
    ("flask.", "Flask"),
    ("rails", "Ruby on Rails"),
    ("ActiveRecord::", "Ruby on Rails"),
    ("NoMethodError", "Ruby"),
    ("TypeError:", "JavaScript/Python"),
    ("ReferenceError:", "JavaScript"),
    ("at Object.<anonymous>", "Node.js"),
    ("at Module._compile", "Node.js"),
    ("at require (internal", "Node.js"),
    ("UnhandledPromiseRejectionWarning", "Node.js"),
    ("Whoops! There was an error.", "Laravel (PHP)"),
    ("Symfony\\Component", "Symfony (PHP)"),
    ("Whitelabel Error Page", "Spring Boot Whitelabel"),
    ("ASP.NET", "ASP.NET"),
    ("System.NullReferenceException", ".NET"),
    ("System.Exception", ".NET"),
    ("at System.", ".NET"),
)

# Generic debug-mode indicators — less severe, informational.
_DEBUG_MARKERS: tuple[str, ...] = (
    "debug mode is on",
    "debug=true",
    "debug=true",
    "DEBUG = True",
    "APP_DEBUG=true",
    "APP_ENV=dev",
    "RAILS_ENV=development",
    "environment: development",
    "laravel.debug",
    "WP_DEBUG",
    "display_errors = On",
    "X-Powered-By: PHP",
)

# Minimum body length — short responses can't contain stack traces.
_MIN_BODY_LENGTH = 50


# ─── Plugin ───────────────────────────────────────────────────────────────────


class VerboseErrorsPlugin(BasePlugin):
    """Detects verbose error pages and debug mode exposure in responses."""

    name = "verbose_errors"
    description = "Detect stack traces, debug mode, and framework error pages in responses"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        try:
            async with session.get(target, allow_redirects=True, ssl=False) as resp:
                body = await fetch_body(resp)
                status = resp.status
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return findings

        if len(body) < _MIN_BODY_LENGTH:
            return findings

        # Check for stack-trace markers (MEDIUM, FIRM).
        found_frameworks: list[str] = []
        for marker, framework in _STACK_TRACE_MARKERS:
            if marker in body:
                if framework not in found_frameworks:
                    found_frameworks.append(framework)

        if found_frameworks:
            findings.append(Finding(
                plugin=self.name,
                title=f"Verbose error page leaks stack trace ({', '.join(found_frameworks)})",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                description=(
                    f"The response body contains stack-trace markers from "
                    f"{', '.join(found_frameworks)}. This indicates the "
                    "application is running with debug/verbose-error mode "
                    "enabled in production. Stack traces leak file paths, "
                    "internal library versions, and sometimes environment "
                    "variables and database credentials."
                ),
                url=target,
                evidence={
                    "frameworks": found_frameworks,
                    "http_status": status,
                    "body_length": len(body),
                },
                remediation=(
                    "Disable debug mode in production. Set "
                    "`DEBUG=False` (Django), `APP_DEBUG=false` (Laravel), "
                    "`RAILS_ENV=production` (Rails), `display_errors = Off` "
                    "(PHP), or `NODE_ENV=production` (Node.js). Configure a "
                    "custom 500 error page that doesn't leak internals."
                ),
            ))
            return findings

        # Check for generic debug markers (LOW, INFORMATIONAL).
        for marker in _DEBUG_MARKERS:
            if marker.lower() in body.lower():
                findings.append(Finding(
                    plugin=self.name,
                    title=f"Debug mode indicator detected: '{marker}'",
                    severity=Severity.LOW,
                    confidence=Confidence.INFORMATIONAL,
                    description=(
                        f"The response body contains a debug-mode indicator "
                        f"('{marker}'). This suggests the application may be "
                        "running in development mode. No stack trace was "
                        "found, but the indicator itself is a signal that "
                        "debug mode might be enabled."
                    ),
                    url=target,
                    evidence={
                        "debug_marker": marker,
                        "http_status": status,
                    },
                    remediation=(
                        "Disable debug mode in production. The indicator "
                        f"'{marker}' should not appear in production responses."
                    ),
                ))
                break  # one debug finding is enough

        return findings
