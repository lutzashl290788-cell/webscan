"""Plugin: detect reflected cross-site scripting (XSS) in query parameters."""
from __future__ import annotations

import asyncio
import html as html_lib
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin

# A unique, unlikely-to-collide marker wrapping the probe so reflections are
# attributable to our injection rather than pre-existing page content.
_MARKER = "wsx9z7"

# Each probe carries breakout characters whose *unescaped* reflection signals an
# exploitable context. The marker brackets the payload for reliable matching.
_PROBES: list[tuple[str, str]] = [
    ("html_tag", f"<{_MARKER}>"),
    ("attr_break", f'"{_MARKER}"'),
    ("js_break", f"';{_MARKER};'"),
    ("svg", f"<svg/{_MARKER}=1>"),
]


class XssPlugin(BasePlugin):
    """Probes each URL query parameter for reflected XSS."""

    name = "xss"
    description = "Detect reflected XSS in URL query parameters"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        if not params:
            return findings

        for param_name in params:
            for context, payload in _PROBES:
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = parsed._replace(
                    query=urlencode(test_params, doseq=True)
                ).geturl()

                try:
                    async with session.get(test_url, ssl=False) as resp:
                        body = await resp.text(errors="ignore")
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

                # Reflected verbatim → dangerous. If only the HTML-escaped form
                # appears, the app is encoding output correctly → not a finding.
                if payload not in body:
                    continue
                if payload == html_lib.escape(payload):
                    continue  # payload had nothing to escape; skip noise

                findings.append(
                    Finding(
                        plugin=self.name,
                        title=f"Reflected XSS in parameter '{param_name}'",
                        severity=Severity.HIGH,
                        description=(
                            f"The value of parameter '{param_name}' is reflected "
                            "into the response without proper output encoding, "
                            f"allowing HTML/JavaScript injection ({context} context)."
                        ),
                        url=test_url,
                        evidence={
                            "parameter": param_name,
                            "payload": payload,
                            "context": context,
                        },
                        remediation=(
                            "Context-aware output encoding (HTML entity, attribute, "
                            "JS, or URL encoding) for all user-controlled data. "
                            "Apply a strict Content-Security-Policy as defence in depth."
                        ),
                    )
                )
                # One confirmed context per parameter is enough.
                break

        return findings
