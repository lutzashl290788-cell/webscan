"""Plugin: detect client-side prototype pollution via vulnerable JS patterns.

Prototype pollution occurs when a JavaScript library merges user-controlled
objects without checking for `__proto__` or `constructor` keys. An attacker
can pollute `Object.prototype` with arbitrary properties, affecting all
objects in the application.

This plugin is **passive**: it scans the page's HTML and same-origin
JavaScript files for known vulnerable merge/extend/defaults patterns. It
doesn't exploit — it only flags the *presence* of potentially vulnerable code.

Findings:
- **MEDIUM (TENTATIVE)** — response contains a known-vulnerable function
  call pattern (e.g. `$.extend(true, {}, userInput)`).
- **LOW (INFORMATIONAL)** — response contains a merge/extend function but
  no user-controlled input is visible at the call site.
"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins._active_helpers import fetch_body
from webscan.plugins.base import BasePlugin
from webscan.utils.html import parse_html

# Known vulnerable merge/extend patterns. Each: (pattern, description).
_VULNERABLE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\$\.extend\s*\(\s*(?:true|deep)?\s*,\s*\{\s*\}\s*,\s*\w+", re.IGNORECASE),
     "jQuery $.extend with user input as source — CVE-2019-11358"),
    (re.compile(r"\bObject\.assign\s*\(\s*\w+\s*,\s*\w+", re.IGNORECASE),
     "Object.assign with user-controlled source — can pollute if source contains __proto__"),
    (re.compile(r"\bdefaultsDeep\s*\(", re.IGNORECASE),
     "lodash defaultsDeep — CVE-2019-10744"),
    (re.compile(r"\bmerge\s*\(\s*\w+\s*,\s*\w+", re.IGNORECASE),
     "merge function with user input — check for __proto__ filtering"),
    (re.compile(r"\bextend\s*\(\s*\w+\s*,\s*\w+", re.IGNORECASE),
     "extend function with user input — check for __proto__ filtering"),
    (re.compile(r"\bdeepClone\s*\(", re.IGNORECASE),
     "deepClone function — may propagate __proto__ if not filtered"),
)

# Generic merge/extend function definitions (lower severity).
_MERGE_DEFINITIONS: tuple[re.Pattern[str], ...] = (
    re.compile(r"function\s+merge\s*\(", re.IGNORECASE),
    re.compile(r"function\s+extend\s*\(", re.IGNORECASE),
    re.compile(r"function\s+defaults\s*\(", re.IGNORECASE),
    re.compile(r"function\s+deepMerge\s*\(", re.IGNORECASE),
    re.compile(r"const\s+merge\s*=", re.IGNORECASE),
    re.compile(r"const\s+extend\s*=", re.IGNORECASE),
)

_MAX_SCRIPTS = 10
_MIN_BODY_LENGTH = 100


class PrototypePollutionPlugin(BasePlugin):
    """Scans HTML and JS for prototype-pollution-vulnerable merge patterns."""

    name = "prototype_pollution"
    description = "Detect client-side prototype pollution via vulnerable merge/extend patterns"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        try:
            async with session.get(target, allow_redirects=True, ssl=False) as resp:
                content_type = resp.headers.get("Content-Type", "")
                if "html" not in content_type.lower() and not target.endswith((".html", ".htm")):
                    return findings
                body = await fetch_body(resp)
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return findings

        if len(body) < _MIN_BODY_LENGTH:
            return findings

        # Scan inline HTML + same-origin JS.
        texts_to_scan: list[tuple[str, str]] = [(body, target)]
        target_host = urlparse(target).netloc
        page = parse_html(body, base=target)
        scripts = [
            s for s in page.links
            if s.endswith(".js") and urlparse(s).netloc == target_host
        ][:_MAX_SCRIPTS]

        for src in scripts:
            try:
                async with session.get(src, ssl=False) as resp:
                    js = await fetch_body(resp)
                    if js:
                        texts_to_scan.append((js, src))
            except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
                continue

        seen_patterns: set[str] = set()

        for text, location in texts_to_scan:
            # Check for vulnerable call patterns (MEDIUM).
            for pattern, description in _VULNERABLE_PATTERNS:
                match = pattern.search(text)
                if match and description not in seen_patterns:
                    seen_patterns.add(description)
                    findings.append(Finding(
                        plugin=self.name,
                        title=f"Prototype pollution: {description}",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.TENTATIVE,
                        description=(
                            f"The response at `{location}` contains a "
                            f"potentially vulnerable pattern: "
                            f"`{match.group(0)[:80]}`. {description}. "
                            "If the source object is user-controlled (e.g. "
                            "parsed from URL hash or query string), an "
                            "attacker can inject `__proto__` to pollute "
                            "Object.prototype."
                        ),
                        url=target,
                        evidence={
                            "location": location,
                            "matched_pattern": match.group(0)[:120],
                            "description": description,
                        },
                        remediation=(
                            "Upgrade to a patched version of the library "
                            "(jQuery ≥3.4.0, lodash ≥4.17.12). Filter "
                            "`__proto__` and `constructor` keys in custom "
                            "merge functions. Use `Object.create(null)` for "
                            "dictionaries."
                        ),
                    ))
                    break  # one MEDIUM per location

            # Check for merge function definitions (LOW).
            if not any(f.severity is Severity.MEDIUM for f in findings):
                for pattern in _MERGE_DEFINITIONS:
                    match = pattern.search(text)
                    if match:
                        findings.append(Finding(
                            plugin=self.name,
                            title="Merge/extend function defined (check for __proto__ filtering)",
                            severity=Severity.LOW,
                            confidence=Confidence.INFORMATIONAL,
                            description=(
                                f"The response at `{location}` defines a "
                                f"merge/extend function (`{match.group(0)}`). "
                                "Manual review needed: verify the function "
                                "filters `__proto__` and `constructor` keys."
                            ),
                            url=target,
                            evidence={
                                "location": location,
                                "function_definition": match.group(0),
                            },
                            remediation=(
                                "Filter `__proto__` and `constructor` keys "
                                "in merge/extend functions. Use "
                                "`Object.create(null)` for dictionaries."
                            ),
                        ))
                        break

        return findings
